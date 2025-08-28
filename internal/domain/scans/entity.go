package scans

import (
	"time"
)

// ID tipe untuk Scan
type ScanID string

// Tool enum
type Tool string

const (
	ToolSQLMap   Tool= "sqlmap"
	ToolTrivy    Tool = "trivy"
	ToolGitleaks Tool = "gitleaks"
	ToolZAP      Tool = "zap"
	ToolNuclei   Tool = "nuclei"
)

// Status enum
type Status string

const (
	StatusSuccess Status = "success"
	StatusFailed  Status = "failed"
)

// SeverityCounts value object
type SeverityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Total    int `json:"total"`
}

// Aggregate Root: Scan
type Scan struct {
	ID          ScanID         `json:"id"`
	TenantID    string         `json:"tenant_id"`
	TriggeredAt time.Time      `json:"triggered_at"`
	Tool        Tool           `json:"tool"`
	Target      string         `json:"target,omitempty"`
	Image       string         `json:"image,omitempty"`
	Path        string         `json:"path,omitempty"`
	Status      Status         `json:"status"`
	Counts      SeverityCounts `json:"counts"`
	ArtifactURL string         `json:"artifact_url,omitempty"`
	RawFormat   string         `json:"raw_format,omitempty"`
	DurationMS  int64          `json:"duration_ms"`
	Source      string         `json:"source,omitempty"`
	CommitSHA   string         `json:"commit_sha,omitempty"`
	Branch      string         `json:"branch,omitempty"`
	Metadata    any            `json:"metadata,omitempty"`
}
