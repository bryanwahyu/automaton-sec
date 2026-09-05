package middleware

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"time"
)

// HealthChecker defines interface for health checking
type HealthChecker interface {
	Check(ctx context.Context) error
}

// DatabaseHealthChecker checks database health
type DatabaseHealthChecker struct {
	DB *sql.DB
}

func (d *DatabaseHealthChecker) Check(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return d.DB.PingContext(ctx)
}

// HealthStatus represents the health status
type HealthStatus struct {
	Status    string                 `json:"status"`
	Timestamp time.Time              `json:"timestamp"`
	Checks    map[string]CheckStatus `json:"checks"`
}

// CheckStatus represents individual check status
type CheckStatus struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

// HealthHandler creates a health check handler
func HealthHandler(checkers map[string]HealthChecker) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		health := HealthStatus{
			Status:    "healthy",
			Timestamp: time.Now(),
			Checks:    make(map[string]CheckStatus),
		}

		// Run all health checks
		for name, checker := range checkers {
			if err := checker.Check(ctx); err != nil {
				health.Status = "unhealthy"
				health.Checks[name] = CheckStatus{
					Status:  "unhealthy",
					Message: err.Error(),
				}
			} else {
				health.Checks[name] = CheckStatus{
					Status: "healthy",
				}
			}
		}

		// Set status code based on health
		statusCode := http.StatusOK
		if health.Status == "unhealthy" {
			statusCode = http.StatusServiceUnavailable
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		json.NewEncoder(w).Encode(health)
	}
}

// ReadinessHandler creates a readiness check handler (simpler than health)
func ReadinessHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "ready",
		"timestamp": time.Now(),
	})
}

// LivenessHandler creates a liveness check handler (simplest check)
func LivenessHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}
