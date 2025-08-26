package scans
import "time"
import "context"

// Repository port (interface untuk persistence)
type Repository interface {
	Save(ctx context.Context, s *Scan) error
	Get(ctx context.Context, tenant string, id ScanID) (*Scan, error)
	Latest(ctx context.Context, tenant string, limit int) ([]*Scan, error)
	Summary(ctx context.Context, tenant string, sinceDays int) (int, int, int, int, error)

	// tambahan paginate
	Paginate(ctx context.Context, tenant string, page, pageSize int) ([]*Scan, error)
	Cursor(ctx context.Context, tenant string, cursorTime time.Time, cursorID string, pageSize int) ([]*Scan, error)
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
