package scanerrors

import "time"

// ScanError represents a persisted scan error entry
type ScanError struct {
    ID         int64     `json:"id"`
    TenantID   string    `json:"tenant_id"`
    ScanID     string    `json:"scan_id"`
    Tool       string    `json:"tool,omitempty"`
    Phase      string    `json:"phase,omitempty"` // trigger | retry | other
    Message    string    `json:"message"`
    DetailsJSON string   `json:"details_json,omitempty"` // raw JSON string
    CreatedAt  time.Time `json:"created_at"`
}

