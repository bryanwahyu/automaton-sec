package httpserver

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"

	"github.com/bryanwahyu/automaton-sec/internal/application"
	appai "github.com/bryanwahyu/automaton-sec/internal/application/ai"
	appscans "github.com/bryanwahyu/automaton-sec/internal/application/scans"
	domai "github.com/bryanwahyu/automaton-sec/internal/domain/ai"
	anldom "github.com/bryanwahyu/automaton-sec/internal/domain/analyst"
	serrdom "github.com/bryanwahyu/automaton-sec/internal/domain/scanerrors"
	domain "github.com/bryanwahyu/automaton-sec/internal/domain/scans"
	"github.com/bryanwahyu/automaton-sec/internal/middleware"
)

// Deps is everything the router needs. It is a struct rather than a parameter
// list so that adding a dependency does not silently reorder arguments at the
// call site.
type Deps struct {
	ScansSvc *appscans.Service
	AISvc    *appai.Service
	ScanErrs serrdom.Repository
	// Pool bounds background scan execution.
	Pool *application.Pool
	// Policy rejects unsafe scan targets before a scan is queued, so the
	// caller gets a 400 instead of a silent background failure.
	Policy domain.TargetPolicy
	Auth   AuthConfig
	// CORSOrigins is the allowlist sent to browsers. Empty means no
	// cross-origin access.
	CORSOrigins []string
	// DBHealth backs GET /healthz. Nil omits that endpoint.
	DBHealth *middleware.DatabaseHealthChecker
	// RateLimitBurst and RateLimitPerMinute bound requests per tenant+IP.
	RateLimitBurst     int
	RateLimitPerMinute int
}

type Router struct {
	scansSvc *appscans.Service
	aiSvc    *appai.Service
	serrRepo serrdom.Repository
	pool     *application.Pool
	policy   domain.TargetPolicy
}

func NewRouter(deps Deps) http.Handler {
	r := &Router{
		scansSvc: deps.ScansSvc,
		aiSvc:    deps.AISvc,
		serrRepo: deps.ScanErrs,
		pool:     deps.Pool,
		policy:   deps.Policy,
	}
	mux := chi.NewRouter()

	origins := deps.CORSOrigins
	if origins == nil {
		origins = []string{}
	}
	mux.Use(cors.Handler(cors.Options{
		AllowedOrigins: origins,
		AllowedMethods: []string{
			"GET", "POST", "PUT", "DELETE", "OPTIONS",
		},
		AllowedHeaders: []string{
			"Accept", "Authorization", "Content-Type", "X-CSRF-Token",
			"X-Requested-With", "Origin", "Cache-Control", "Pragma", "X-Signature",
		},
		ExposedHeaders: []string{
			"Link", "Content-Length", "Content-Range",
		},
		AllowCredentials: false,
		MaxAge:           300, // Maximum value not ignored by any of major browsers
	}))

	mux.Use(middleware.LoggingMiddleware)
	mux.Use(middleware.MetricsMiddleware)

	// Unauthenticated on purpose: probes and scrapers must not need a
	// credential, and none of these expose scan data.
	mux.Get("/health", middleware.LivenessHandler)
	mux.Get("/ready", middleware.ReadinessHandler)
	mux.Get("/metrics", middleware.MetricsHandler)
	if deps.DBHealth != nil {
		mux.Get("/healthz", middleware.HealthHandler(map[string]middleware.HealthChecker{
			"database": deps.DBHealth,
		}))
	}

	// Tokens refill per second; the config expresses the sustained rate per
	// minute because that is the easier number to reason about.
	//
	// Both values are clamped: a zero burst would build a bucket that can never
	// hand out a token, turning the limiter into a blanket 429.
	burst := deps.RateLimitBurst
	if burst < 1 {
		burst = 20
	}
	refillPerSecond := deps.RateLimitPerMinute / 60
	if refillPerSecond < 1 {
		refillPerSecond = 1
	}

	mux.Route("/v1/{tenant}", func(rt chi.Router) {
		rt.Use(middleware.RateLimitMiddleware(burst, refillPerSecond))
		rt.Use(requireValidTenant)

		// Triggering a scan is signed with the webhook secret.
		rt.Group(func(sec chi.Router) {
			sec.Use(deps.Auth.requireWebhookSignature)
			sec.Post("/webhook/security-scan", r.wrap(r.handleTriggerScan))
		})

		// Everything else takes a bearer API key.
		rt.Group(func(sec chi.Router) {
			sec.Use(deps.Auth.requireAPIKey)
			sec.Post("/scans/{id}/retry", r.wrap(r.handleRetryScan))
			sec.Get("/scans/{id}/errors", r.wrap(r.handleListScanErrors))
			sec.Get("/scans/latest", r.wrap(r.handleLatest))
			sec.Get("/scans", r.wrap(r.handleListScans)) // paginated list
			sec.Get("/scans/{id}", r.wrap(r.handleGet))
			sec.Get("/summary", r.wrap(r.handleSummary))
			sec.Post("/ai/analyze", r.wrap(r.handleAIAnalyze))
			sec.Get("/ai/analyze", r.wrap(r.handleAIAnalyzeList))
			sec.Post("/ai/analyze/retry", r.wrap(r.handleAIAnalyzeRetry))
		})
	})

	return mux
}

// requireValidTenant rejects a malformed tenant segment before it reaches a
// handler, a query, or an artifact storage key.
func requireValidTenant(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if err := middleware.ValidateTenantID(chi.URLParam(req, "tenant")); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		next.ServeHTTP(w, req)
	})
}

// badRequest marks an error as caller error so wrap answers 400 instead of 500.
type badRequest struct{ error }

func (b badRequest) Unwrap() error { return b.error }

func errBadRequest(err error) error { return badRequest{err} }

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
			if errors.Is(err, application.ErrBusy) {
				w.Header().Set("Retry-After", "60")
				http.Error(w, "scanner capacity reached, retry later", http.StatusTooManyRequests)
				return
			}
			var bad badRequest
			if errors.As(err, &bad) {
				http.Error(w, err.Error(), http.StatusBadRequest)
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

// POST /v1/{tenant}/ai/analyze/retry?scan_id=<id>&analysis_id=<optional-existing-id>
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
//
// Validates the request, queues the scan on the bounded worker pool, and
// answers 202 immediately. A saturated pool answers 429; an unusable target
// answers 400 rather than failing silently in the background.
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
		return errBadRequest(fmt.Errorf("invalid JSON body: %w", err))
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

	// Reject unusable input up front so the caller sees the reason.
	if err := r.policy.ValidateRunRequest(domain.RunRequest{
		Tool:   domain.Tool(cmd.Tool),
		Mode:   cmd.Mode,
		Image:  cmd.Image,
		Path:   cmd.Path,
		Target: cmd.Target,
	}); err != nil {
		return errBadRequest(err)
	}

	queuedAt := time.Now()
	err := r.pool.Submit(func(ctx context.Context) {
		result, err := r.scansSvc.TriggerScan(ctx, cmd)
		if err != nil {
			log.Printf("scan failed tenant=%s tool=%s id=%s: %v", tenant, body.Tool, result.ID, err)
			// TriggerScan has already marked the row as error; record the
			// detail for troubleshooting.
			r.recordScanError(tenant, result.ID, body.Tool, "trigger", err)
			return
		}
		log.Printf("scan finished tenant=%s tool=%s id=%s status=%s artifact=%s",
			tenant, body.Tool, result.ID, result.Status, result.ArtifactURL)
	})
	if err != nil {
		return err
	}

	resp := map[string]any{
		"status":   "queued",
		"tenant":   tenant,
		"tool":     body.Tool,
		"branch":   body.Branch,
		"commit":   body.CommitSHA,
		"message":  "scan started in background",
		"queuedAt": queuedAt,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	return json.NewEncoder(w).Encode(resp)
}

// recordScanError stores a background failure so it can be read back through
// GET /v1/{tenant}/scans/{id}/errors.
func (r *Router) recordScanError(tenant, scanID, tool, phase string, cause error) {
	if r.serrRepo == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	details, _ := json.Marshal(map[string]any{
		"status": "error",
		"type":   "scan_error_" + phase,
		"time":   time.Now().Format(time.RFC3339Nano),
	})
	if err := r.serrRepo.Save(ctx, &serrdom.ScanError{
		TenantID:    tenant,
		ScanID:      scanID,
		Tool:        tool,
		Phase:       phase,
		Message:     cause.Error(),
		DetailsJSON: string(details),
	}); err != nil {
		log.Printf("could not record scan error tenant=%s scan=%s: %v", tenant, scanID, err)
	}
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
			for len(seg) > 0 && (seg[0] == ' ' || seg[0] == '\t') {
				seg = seg[1:]
			}
			for len(seg) > 0 && (seg[len(seg)-1] == ' ' || seg[len(seg)-1] == '\t') {
				seg = seg[:len(seg)-1]
			}
			if seg != "" {
				out = append(out, seg)
			}
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
//
// Re-runs a scan that previously failed. Queued on the same bounded pool as a
// fresh scan, so a retry storm cannot starve the service.
func (r *Router) handleRetryScan(w http.ResponseWriter, req *http.Request) error {
	tenant := chi.URLParam(req, "tenant")
	id := chi.URLParam(req, "id")

	// Confirm the scan exists before promising a retry.
	if _, err := r.scansSvc.Get(req.Context(), tenant, domain.ScanID(id)); err != nil {
		return err
	}

	err := r.pool.Submit(func(ctx context.Context) {
		result, err := r.scansSvc.RetryScan(ctx, tenant, domain.ScanID(id))
		if err != nil {
			log.Printf("retry scan failed tenant=%s id=%s: %v", tenant, id, err)
			r.recordScanError(tenant, id, "", "retry", err)
			return
		}
		log.Printf("retry scan finished tenant=%s id=%s status=%s artifact=%s",
			tenant, id, result.Status, result.ArtifactURL)
	})
	if err != nil {
		return err
	}

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
