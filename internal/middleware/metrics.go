package middleware

import (
	"encoding/json"
	"net/http"
	"runtime"
	"sync/atomic"
	"time"
)

// Metrics stores application metrics
type Metrics struct {
	RequestsTotal      uint64
	RequestsInProgress uint64
	RequestsSuccess    uint64
	RequestsFailed     uint64
	ScansTotal         uint64
	ScansRunning       uint64
	ScansFailed        uint64
	StartTime          time.Time
}

var globalMetrics = &Metrics{
	StartTime: time.Now(),
}

// IncrementRequests increments total request counter
func IncrementRequests() {
	atomic.AddUint64(&globalMetrics.RequestsTotal, 1)
}

// IncrementInProgress increments in-progress request counter
func IncrementInProgress() {
	atomic.AddUint64(&globalMetrics.RequestsInProgress, 1)
}

// DecrementInProgress decrements in-progress request counter
func DecrementInProgress() {
	atomic.AddUint64(&globalMetrics.RequestsInProgress, ^uint64(0))
}

// IncrementSuccess increments successful request counter
func IncrementSuccess() {
	atomic.AddUint64(&globalMetrics.RequestsSuccess, 1)
}

// IncrementFailed increments failed request counter
func IncrementFailed() {
	atomic.AddUint64(&globalMetrics.RequestsFailed, 1)
}

// IncrementScans increments total scans counter
func IncrementScans() {
	atomic.AddUint64(&globalMetrics.ScansTotal, 1)
}

// IncrementScansRunning increments running scans counter
func IncrementScansRunning() {
	atomic.AddUint64(&globalMetrics.ScansRunning, 1)
}

// DecrementScansRunning decrements running scans counter
func DecrementScansRunning() {
	atomic.AddUint64(&globalMetrics.ScansRunning, ^uint64(0))
}

// IncrementScansFailed increments failed scans counter
func IncrementScansFailed() {
	atomic.AddUint64(&globalMetrics.ScansFailed, 1)
}

// GetMetrics returns current metrics
func GetMetrics() map[string]interface{} {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	return map[string]interface{}{
		"requests_total":       atomic.LoadUint64(&globalMetrics.RequestsTotal),
		"requests_in_progress": atomic.LoadUint64(&globalMetrics.RequestsInProgress),
		"requests_success":     atomic.LoadUint64(&globalMetrics.RequestsSuccess),
		"requests_failed":      atomic.LoadUint64(&globalMetrics.RequestsFailed),
		"scans_total":          atomic.LoadUint64(&globalMetrics.ScansTotal),
		"scans_running":        atomic.LoadUint64(&globalMetrics.ScansRunning),
		"scans_failed":         atomic.LoadUint64(&globalMetrics.ScansFailed),
		"uptime_seconds":       time.Since(globalMetrics.StartTime).Seconds(),
		"memory": map[string]interface{}{
			"alloc_bytes":       m.Alloc,
			"total_alloc_bytes": m.TotalAlloc,
			"sys_bytes":         m.Sys,
			"num_gc":            m.NumGC,
		},
		"goroutines": runtime.NumGoroutine(),
	}
}

// MetricsMiddleware tracks request metrics
func MetricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		IncrementRequests()
		IncrementInProgress()
		defer DecrementInProgress()

		// Wrap response writer to capture status
		wrapped := &responseWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}

		next.ServeHTTP(wrapped, r)

		// Track success/failure based on status code
		if wrapped.statusCode >= 200 && wrapped.statusCode < 400 {
			IncrementSuccess()
		} else {
			IncrementFailed()
		}
	})
}

// MetricsHandler returns metrics as JSON
func MetricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(GetMetrics())
}
