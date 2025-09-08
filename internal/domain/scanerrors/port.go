package scanerrors

import (
    "context"
)

// Repository defines persistence for scan errors
type Repository interface {
    Save(ctx context.Context, e *ScanError) error
    ListByScan(ctx context.Context, tenant string, scanID string, limit int) ([]*ScanError, error)
}

