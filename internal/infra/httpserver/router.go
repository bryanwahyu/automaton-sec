package httpserver

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"
	"fmt"
	"github.com/go-chi/chi/v5"
	appscans "github.com/bryanwahyu/automaton-sec/internal/application/scans"
	domain "github.com/bryanwahyu/automaton-sec/internal/domain/scans"
)

type Router struct {
	svc     *appscans.Service
	hmacKey []byte
}

func NewRouter(svc *appscans.Service, hmacKey []byte) http.Handler {
	r := &Router{svc: svc, hmacKey: hmacKey}
	mux := chi.NewRouter()

	mux.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	mux.Route("/v1/{tenant}", func(rt chi.Router) {
		rt.Post("/webhook/security-scan", r.wrap(r.handleTriggerScan))
		rt.Get("/scans/latest", r.wrap(r.handleLatest))
		rt.Get("/scans/{id}", r.wrap(r.handleGet))
		rt.Get("/summary", r.wrap(r.handleSummary))
	})

	return mux
}

type handlerFunc func(http.ResponseWriter, *http.Request) error

func (r *Router) wrap(h handlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if err := h(w, req); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
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
		_ = r.svc.UpdateStatus(cmd.TenantID, "running")

		result, err := r.svc.TriggerScanUntilDone(cmd)
		if err != nil {
			fmt.Printf("background scan error for tenant=%s tool=%s: %v\n",
				tenant, body.Tool, err)
			_ = r.svc.UpdateStatus(cmd.TenantID, "failed")
			return
		}

		// kalau berhasil → mark done
		_ = r.svc.MarkDone(cmd.TenantID, result)
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

// GET /v1/{tenant}/scans/latest?limit=20
func (r *Router) handleLatest(w http.ResponseWriter, req *http.Request) error {
	tenant := chi.URLParam(req, "tenant")
	limit, _ := strconv.Atoi(req.URL.Query().Get("limit"))

	list, err := r.svc.Latest(req.Context(), tenant, limit)
	if err != nil {
		return err
	}

	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(list)
}

// GET /v1/{tenant}/scans/{id}
func (r *Router) handleGet(w http.ResponseWriter, req *http.Request) error {
	tenant := chi.URLParam(req, "tenant")
	id := chi.URLParam(req, "id")

	scan, err := r.svc.Get(req.Context(), tenant, domain.ScanID(id))
	if err != nil {
		return err
	}

	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(scan)
}

// GET /v1/{tenant}/summary?days=7
func (r *Router) handleSummary(w http.ResponseWriter, req *http.Request) error {
	tenant := chi.URLParam(req, "tenant")
	days, _ := strconv.Atoi(req.URL.Query().Get("days"))

	summary, err := r.svc.Summary(req.Context(), tenant, days)
	if err != nil {
		return err
	}

	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(summary)
}
