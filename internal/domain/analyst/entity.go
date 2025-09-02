package analyst

import "time"

// AnalysisID identifier type
type AnalysisID string

// Analysis represents an AI analysis result stored for auditing and retrieval
type Analysis struct {
    ID        AnalysisID `json:"id"`
    TenantID  string     `json:"tenant_id"`
    ScanID    string     `json:"scan_id,omitempty"`
    FileURL   string     `json:"file_url"`
    Result    string     `json:"result"` // JSON string from AI
    CreatedAt time.Time  `json:"created_at"`
}
