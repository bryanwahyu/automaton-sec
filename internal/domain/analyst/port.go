package analyst

import "context"

// Repository port for persisting and querying analyses
type Repository interface {
    Save(ctx context.Context, a *Analysis) error
    Paginate(ctx context.Context, tenant string, page, pageSize int) ([]*Analysis, error)
    LatestByScan(ctx context.Context, tenant string, scanID string) (*Analysis, error)
}
