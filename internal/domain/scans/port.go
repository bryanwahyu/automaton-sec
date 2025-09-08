package scans

import (
	"context"
	"time"
)


// Repository port (interface untuk persistence)
type Repository interface {
	Save(ctx context.Context, s *Scan) error
	Get(ctx context.Context, tenant string, id ScanID) (*Scan, error)
	Latest(ctx context.Context, tenant string, limit int) ([]*Scan, error)
	Summary(ctx context.Context, tenant string, sinceDays int) (int, int, int, int, error)
	// tambahan untuk background mode
	UpdateStatus(ctx context.Context, tenant string, status Status) error
	UpdateResult(ctx context.Context, tenant string, id ScanID, status Status, artifactURL string, counts SeverityCounts) error
	// update only counts for a given scan id
	UpdateCounts(ctx context.Context, tenant string, id ScanID, counts SeverityCounts) error
	// tambahan pagination dan filtering
	Paginate(ctx context.Context, tenant string, page, pageSize int, filters map[string]interface{}) (PaginatedResult, error)
	Cursor(ctx context.Context, tenant string, cursorTime time.Time, cursorID string, pageSize int) ([]*Scan, error)
	// Get total count for pagination
	Count(ctx context.Context, tenant string, filters map[string]interface{}) (int64, error)
}

// Runner port (interface untuk eksekusi scanner)
type Runner interface {
	Run(ctx context.Context, req RunRequest) (RunResult, error)
}

// ArtifactStore port (interface untuk penyimpanan artefak)
type ArtifactStore interface {
	Upload(ctx context.Context, localPath, key string) (string, error)
	UploadAndCleanup(ctx context.Context, localPath, key string) (string, error)
}
