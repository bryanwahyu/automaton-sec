package httpserver

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"

	appai "github.com/bryanwahyu/automaton-sec/internal/application/ai"
	appscans "github.com/bryanwahyu/automaton-sec/internal/application/scans"
	domai "github.com/bryanwahyu/automaton-sec/internal/domain/ai"
	anldom "github.com/bryanwahyu/automaton-sec/internal/domain/analyst"
	serrdom "github.com/bryanwahyu/automaton-sec/internal/domain/scanerrors"
	domain "github.com/bryanwahyu/automaton-sec/internal/domain/scans"
)

type Router struct {
	scansSvc *appscans.Service
	aiSvc    *appai.Service
	serrRepo serrdom.Repository
	hmacKey  []byte
}

func NewRouter(scansSvc *appscans.Service, aiSvc *appai.Service, serrRepo serrdom.Repository, hmacKey []byte) http.Handler {
	r := &Router{scansSvc: scansSvc, aiSvc: aiSvc, serrRepo: serrRepo, hmacKey: hmacKey}
	mux := chi.NewRouter()

	// Configure CORS middleware with all origins allowed (*)
	mux.Use(cors.Handler(cors.Options{
		AllowedOrigins: []string{"*"}, // Allow all origins
		AllowedMethods: []string{
			"GET", "POST", "PUT", "DELETE", "OPTIONS",
		},
		AllowedHeaders: []string{
			"Accept", "Authorization", "Content-Type", "X-CSRF-Token",
			"X-Requested-With", "Origin", "Cache-Control", "Pragma",
		},
		ExposedHeaders: []string{
			"Link", "Content-Length", "Content-Range",
		},
		AllowCredentials: false, // Must be false when AllowedOrigins is "*"
		MaxAge:           300,   // Maximum value not ignored by any of major browsers
	}))

	mux.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	mux.Route("/v1/{tenant}", func(rt chi.Router) {
		rt.Post("/webhook/security-scan", r.wrap(r.handleTriggerScan))
		rt.Get("/scans/{id}/retry", r.wrap(r.handleRetryScan))
		rt.Get("/scans/{id}/errors", r.wrap(r.handleListScanErrors))
		rt.Get("/scans/latest", r.wrap(r.handleLatest))
		rt.Get("/scans", r.wrap(r.handleListScans)) // New endpoint for paginated list
		rt.Get("/scans/{id}", r.wrap(r.handleGet))
		rt.Get("/summary", r.wrap(r.handleSummary))
        rt.Post("/ai/analyze", r.wrap(r.handleAIAnalyze))
        rt.Get("/ai/analyze", r.wrap(r.handleAIAnalyzeList))
        rt.Get("/ai/analyze/retry", r.wrap(r.handleAIAnalyzeRetry))
	})

	return mux
}

type handlerFunc func(http.ResponseWriter, *http.Request) error

func (r *Router) wrap(h handlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if err := h(w, req); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			if errors.Is(err, domai.ErrQuotaExceeded) {
				http.Error(w, "ai quota exceeded", http.StatusTooManyRequests)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

// POST /v1/{tenant}/ai/analyze
// Body: {"scan_id": "<id>"}
// The server will fetch the corresponding scan's artifact_url and run AI analysis on it.
func (r *Router) handleAIAnalyze(w http.ResponseWriter, req *http.Request) error {
	tenant := chi.URLParam(req, "tenant")
	var body struct {
		ScanID string `json:"scan_id"`
	}
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		return err
	}
	if body.ScanID == "" {
		return fmt.Errorf("scan_id is required")
	}

	// Lookup scan to get artifact URL
	scan, err := r.scansSvc.Get(req.Context(), tenant, domain.ScanID(body.ScanID))
	if err != nil {
		return err
	}
	if scan == nil || scan.ArtifactURL == "" {
		return fmt.Errorf("artifact_url not found for scan_id: %s", body.ScanID)
	}

	// Enqueue immediate placeholder record and run analysis in background
	queued, err := r.aiSvc.QueueAnalysis(req.Context(), tenant, body.ScanID, scan.ArtifactURL)
	if err != nil {
		return err
	}

	go func() {
		if _, err := r.aiSvc.AnalyzeAndStoreWithID(context.Background(), tenant, body.ScanID, queued.ID, scan.ArtifactURL); err != nil {
			fmt.Printf("background ai analyze error tenant=%s scan_id=%s: %v\n", tenant, body.ScanID, err)
		}
	}()

	// Reply immediately
	resp := map[string]any{
		"status":      "queued",
		"tenant":      tenant,
		"scan_id":     body.ScanID,
		"analysis_id": queued.ID,
		"message":     "AI analysis started in background, tunggu sebentar ya",
		"queuedAt":    queued.CreatedAt,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	return json.NewEncoder(w).Encode(resp)
}

// GET /v1/{tenant}/ai/analyze/retry?scan_id=<id>&analysis_id=<optional-existing-id>
// Forces an immediate retry by queueing (or marking retry) and starting background analysis.
func (r *Router) handleAIAnalyzeRetry(w http.ResponseWriter, req *http.Request) error {
    tenant := chi.URLParam(req, "tenant")
    scanID := req.URL.Query().Get("scan_id")
    analysisID := req.URL.Query().Get("analysis_id")
    if scanID == "" {
        return fmt.Errorf("scan_id is required")
    }

    // Lookup scan to get artifact URL
    scan, err := r.scansSvc.Get(req.Context(), tenant, domain.ScanID(scanID))
    if err != nil {
        return err
    }
    if scan == nil || scan.ArtifactURL == "" {
        return fmt.Errorf("artifact_url not found for scan_id: %s", scanID)
    }

    var queuedID anldom.AnalysisID
    if analysisID != "" {
        queuedID = anldom.AnalysisID(analysisID)
        // Mark status as retry_requested
        r.aiSvc.UpdateAnalysisStatus(req.Context(), tenant, scanID, queuedID, scan.ArtifactURL, map[string]any{
            "status":      "retry_requested",
            "requestedAt": time.Now(),
        })
    } else {
        // Create a new queued record to track this retry
        queued, err := r.aiSvc.QueueAnalysis(req.Context(), tenant, scanID, scan.ArtifactURL)
        if err != nil {
            return err
        }
        queuedID = queued.ID
    }

    // Start background work immediately (ignores scheduled backoff)
    go func(id anldom.AnalysisID) {
        if _, err := r.aiSvc.AnalyzeAndStoreWithID(context.Background(), tenant, scanID, id, scan.ArtifactURL); err != nil {
            fmt.Printf("manual retry ai analyze error tenant=%s scan_id=%s: %v\n", tenant, scanID, err)
        }
    }(queuedID)

    // Respond 202
    resp := map[string]any{
        "status":      "queued",
        "tenant":      tenant,
        "scan_id":     scanID,
        "analysis_id": queuedID,
        "message":     "AI analysis retry queued, akan diproses di background",
        "queuedAt":    time.Now(),
    }
    w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	return json.NewEncoder(w).Encode(resp)
}

// GET /v1/{tenant}/ai/analyze?page=&page_size=
func (r *Router) handleAIAnalyzeList(w http.ResponseWriter, req *http.Request) error {
	tenant := chi.URLParam(req, "tenant")
	page, _ := strconv.Atoi(req.URL.Query().Get("page"))
	size, _ := strconv.Atoi(req.URL.Query().Get("page_size"))

	list, err := r.aiSvc.ListAnalyses(req.Context(), tenant, page, size)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(list)
}

// POST /v1/{tenant}/webhook/security-scan
func (r *Router) handleTriggerScan(w http.ResponseWriter, req *http.Request) error {
	tenant := chi.URLParam(req, "tenant")

	var body struct {
		Tool      string `json:"tool"`
		Mode      string `json:"mode"`
		Image     string `json:"image"`
		Path      string `json:"path"`
		Target    string `json:"target"`
		Source    string `json:"source"`
		CommitSHA string `json:"commit_sha"`
		Branch    string `json:"branch"`
		Metadata  any    `json:"metadata"`
	}
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		return err
	}

	cmd := appscans.TriggerScanCommand{
		TenantID:  tenant,
		Tool:      body.Tool,
		Mode:      body.Mode,
		Image:     body.Image,
		Path:      body.Path,
		Target:    body.Target,
		Source:    body.Source,
		CommitSHA: body.CommitSHA,
		Branch:    body.Branch,
		Metadata:  body.Metadata,
	}

	// 🚀 Jalankan di background, biar jalan sampai selesai
	go func() {
		// update status ke running
		_ = r.scansSvc.UpdateStatus(cmd.TenantID, "running")

		result, err := r.scansSvc.TriggerScanUntilDone(cmd)
		if err != nil {
			fmt.Printf("background scan error for tenant=%s tool=%s id=%s: %v\n",
				tenant, body.Tool, result.ID, err)
			_ = r.scansSvc.UpdateStatus(cmd.TenantID, "error")
			// Simpan error ke tabel khusus supaya mudah dicek
			if r.serrRepo != nil {
				_ = r.serrRepo.Save(context.Background(), &serrdom.ScanError{
					TenantID:    tenant,
					ScanID:      result.ID,
					Tool:        body.Tool,
					Phase:       "trigger",
					Message:     err.Error(),
					DetailsJSON: `{"status":"error","type":"scan_error","time":"` + time.Now().Format(time.RFC3339Nano) + `"}`,
				})
			}
			return
		}

		// kalau berhasil → mark done
		_ = r.scansSvc.MarkDone(cmd.TenantID, result)
		fmt.Printf("scan finished: tenant=%s tool=%s artifact=%s\n",
			tenant, body.Tool, result.ArtifactURL)
	}()

	// 🔙 langsung balikin respons ke client
	resp := map[string]any{
		"status":   "queued",
		"tenant":   tenant,
		"tool":     body.Tool,
		"branch":   body.Branch,
		"commit":   body.CommitSHA,
		"message":  "scan started in background",
		"queuedAt": time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(resp)
}

// GET /v1/{tenant}/scans/latest?limit=20&cursor_time=2006-01-02T15:04:05Z&cursor_id=abc-123
func (r *Router) handleLatest(w http.ResponseWriter, req *http.Request) error {
	tenant := chi.URLParam(req, "tenant")
	limit, _ := strconv.Atoi(req.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 20 // default limit
	}

	cursorTime := req.URL.Query().Get("cursor_time")
	cursorID := req.URL.Query().Get("cursor_id")

	var list []*domain.Scan
	var err error

	// Track if we're on the first page
	isFirstPage := cursorTime == "" || cursorID == ""

	if !isFirstPage {
		// Parse cursor time
		t, err := time.Parse(time.RFC3339, cursorTime)
		if err != nil {
			return fmt.Errorf("invalid cursor_time format: %v", err)
		}
		list, err = r.scansSvc.Cursor(req.Context(), tenant, t, cursorID, limit)
	} else {
		list, err = r.scansSvc.Latest(req.Context(), tenant, limit)
	}
	if err != nil {
		return err
	}

	// Build response with metadata
	meta := map[string]interface{}{
		"limit":         limit,
		"has_more":      len(list) == limit,
		"is_first_page": isFirstPage,
	}

	// Add current cursor information
	if !isFirstPage {
		meta["current_cursor"] = map[string]interface{}{
			"cursor_time": cursorTime,
			"cursor_id":   cursorID,
		}
	}

	// Add next cursor if we have more results
	if len(list) == limit {
		lastItem := list[len(list)-1]
		meta["next_cursor"] = map[string]interface{}{
			"cursor_time": lastItem.TriggeredAt.Format(time.RFC3339),
			"cursor_id":   string(lastItem.ID),
			"next_url": fmt.Sprintf("/v1/%s/scans/latest?limit=%d&cursor_time=%s&cursor_id=%s",
				tenant,
				limit,
				lastItem.TriggeredAt.Format(time.RFC3339),
				string(lastItem.ID)),
		}
	}

	response := map[string]interface{}{
		"data": list,
		"meta": meta,
	}

	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(response)
}

// GET /v1/{tenant}/scans/{id}
// Optional: ?with=analysis (comma-separated supported) to include latest AI analysis
func (r *Router) handleGet(w http.ResponseWriter, req *http.Request) error {
    tenant := chi.URLParam(req, "tenant")
    id := chi.URLParam(req, "id")
    withParam := req.URL.Query().Get("with")

    scan, err := r.scansSvc.Get(req.Context(), tenant, domain.ScanID(id))
    if err != nil {
        return err
    }

    // If with=analysis (or analyze/ai), include latest AI analysis result
    if withParam != "" {
        // support comma-separated values
        includeAnalysis := false
        for _, p := range splitAndTrim(withParam) {
            if p == "analysis" || p == "analyze" || p == "ai" {
                includeAnalysis = true
                break
            }
        }
        if includeAnalysis {
            a, _ := r.aiSvc.LatestByScan(req.Context(), tenant, id)
            resp := map[string]any{
                "scan":     scan,
                "analysis": a,
            }
            w.Header().Set("Content-Type", "application/json")
            return json.NewEncoder(w).Encode(resp)
        }
    }

    w.Header().Set("Content-Type", "application/json")
    return json.NewEncoder(w).Encode(scan)
}

// splitAndTrim splits by comma and trims spaces; empty-safe
func splitAndTrim(s string) []string {
    if s == "" {
        return nil
    }
    var out []string
    start := 0
    for i := 0; i <= len(s); i++ {
        if i == len(s) || s[i] == ',' {
            seg := s[start:i]
            // trim spaces
            for len(seg) > 0 && (seg[0] == ' ' || seg[0] == '\t') { seg = seg[1:] }
            for len(seg) > 0 && (seg[len(seg)-1] == ' ' || seg[len(seg)-1] == '\t') { seg = seg[:len(seg)-1] }
            if seg != "" { out = append(out, seg) }
            start = i + 1
        }
    }
    return out
}

// GET /v1/{tenant}/summary?days=7
func (r *Router) handleSummary(w http.ResponseWriter, req *http.Request) error {
	tenant := chi.URLParam(req, "tenant")
	days, _ := strconv.Atoi(req.URL.Query().Get("days"))

	summary, err := r.scansSvc.Summary(req.Context(), tenant, days)
	if err != nil {
		return err
	}

	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(summary)
}

// GET /v1/{tenant}/scans?page=1&page_size=20&target=example.com
func (r *Router) handleListScans(w http.ResponseWriter, req *http.Request) error {
	tenant := chi.URLParam(req, "tenant")
	page, _ := strconv.Atoi(req.URL.Query().Get("page"))
	pageSize, _ := strconv.Atoi(req.URL.Query().Get("page_size"))
	target := req.URL.Query().Get("target")

	// Build filters
	filters := make(map[string]interface{})
	if target != "" {
		filters["target"] = target
	}

	// Add other possible filters
	if tool := req.URL.Query().Get("tool"); tool != "" {
		filters["tool"] = tool
	}
	if status := req.URL.Query().Get("status"); status != "" {
		filters["status"] = status
	}
	if branch := req.URL.Query().Get("branch"); branch != "" {
		filters["branch"] = branch
	}

	result, err := r.scansSvc.Paginate(req.Context(), tenant, page, pageSize, filters)
	if err != nil {
		return err
	}

	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(result)
}

// POST /v1/{tenant}/scans/{id}/retry
// Jalankan ulang scan yang sebelumnya error/failed. Dijalankan di background.
func (r *Router) handleRetryScan(w http.ResponseWriter, req *http.Request) error {
	tenant := chi.URLParam(req, "tenant")
	id := chi.URLParam(req, "id")

	// Jalankan di background supaya respons cepat
	go func() {
		_ = r.scansSvc.UpdateStatus(tenant, "running")
		result, err := r.scansSvc.RetryScan(context.Background(), tenant, domain.ScanID(id))
		if err != nil {
			fmt.Printf("retry scan error tenant=%s id=%s: %v\n", tenant, id, err)
			_ = r.scansSvc.UpdateStatus(tenant, "error")
			if r.serrRepo != nil {
				_ = r.serrRepo.Save(context.Background(), &serrdom.ScanError{
					TenantID:    tenant,
					ScanID:      id,
					Phase:       "retry",
					Message:     err.Error(),
					DetailsJSON: `{"status":"error","type":"scan_error_retry","time":"` + time.Now().Format(time.RFC3339Nano) + `"}`,
				})
			}
			return
		}
		_ = r.scansSvc.MarkDone(tenant, result)
		fmt.Printf("retry scan finished tenant=%s id=%s artifact=%s\n", tenant, id, result.ArtifactURL)
	}()

	resp := map[string]any{
		"status":   "queued",
		"tenant":   tenant,
		"scan_id":  id,
		"message":  "retry started in background",
		"queuedAt": time.Now(),
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	return json.NewEncoder(w).Encode(resp)
}

// GET /v1/{tenant}/scans/{id}/errors?limit=20
func (r *Router) handleListScanErrors(w http.ResponseWriter, req *http.Request) error {
	tenant := chi.URLParam(req, "tenant")
	id := chi.URLParam(req, "id")
	limit, _ := strconv.Atoi(req.URL.Query().Get("limit"))
	if r.serrRepo == nil {
		return fmt.Errorf("errors repository not configured")
	}
	list, err := r.serrRepo.ListByScan(req.Context(), tenant, id, limit)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(list)
}
