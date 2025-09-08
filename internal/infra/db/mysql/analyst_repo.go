package mysql

import (
    "context"
    "database/sql"
    "strings"
    "time"

    domain "github.com/bryanwahyu/automaton-sec/internal/domain/analyst"
)

type AnalystRepository struct {
    db *sql.DB
}

func NewAnalystRepository(db *sql.DB) *AnalystRepository {
    return &AnalystRepository{db: db}
}

// Save inserts an analysis record
func (r *AnalystRepository) Save(ctx context.Context, a *domain.Analysis) error {
    const q = `
INSERT INTO security_analyze
  (id, tenant_id, scan_id, file_url, result_json, created_at)
VALUES (?,?,?,?,?,?)
ON DUPLICATE KEY UPDATE
  tenant_id=VALUES(tenant_id), scan_id=VALUES(scan_id), file_url=VALUES(file_url), result_json=VALUES(result_json);
`
    // Ensure non-nullable fields have safe defaults
    tenant := stringOrDash(a.TenantID)
    fileURL := stringOrDash(a.FileURL)
    result := a.Result
    if strings.TrimSpace(result) == "" {
        // result_json column requires valid JSON; use empty object
        result = "{}"
    }
    createdAt := a.CreatedAt
    if createdAt.IsZero() {
        createdAt = time.Now()
    }

    _, err := r.db.ExecContext(ctx, q, a.ID, tenant, a.ScanID, fileURL, result, createdAt)
    return err
}

// Paginate returns a page of analysis records ordered by created_at desc
func (r *AnalystRepository) Paginate(ctx context.Context, tenant string, page, pageSize int) ([]*domain.Analysis, error) {
    if page <= 0 {
        page = 1
    }
    if pageSize <= 0 {
        pageSize = 20
    }
    offset := (page - 1) * pageSize

    const q = `
SELECT id, tenant_id, scan_id, file_url, result_json, created_at
FROM security_analyze
WHERE tenant_id=?
ORDER BY created_at DESC, id DESC
LIMIT ? OFFSET ?;
`
    rows, err := r.db.QueryContext(ctx, q, tenant, pageSize, offset)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var out []*domain.Analysis
    for rows.Next() {
        var a domain.Analysis
        var created time.Time
        if err := rows.Scan(&a.ID, &a.TenantID, &a.ScanID, &a.FileURL, &a.Result, &created); err != nil {
            return nil, err
        }
        a.CreatedAt = created
        out = append(out, &a)
    }
    return out, rows.Err()
}
