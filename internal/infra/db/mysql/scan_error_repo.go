package mysql

import (
    "context"
    "database/sql"
    "encoding/json"
    "strings"
    "time"

    domain "github.com/bryanwahyu/automaton-sec/internal/domain/scanerrors"
)

type ScanErrorRepository struct {
    db *sql.DB
}

func NewScanErrorRepository(db *sql.DB) *ScanErrorRepository { return &ScanErrorRepository{db: db} }

func (r *ScanErrorRepository) Save(ctx context.Context, e *domain.ScanError) error {
    const q = `
INSERT INTO security_scan_errors
  (tenant_id, scan_id, tool, phase, message, details_json, created_at)
VALUES (?,?,?,?,?,?,?)
`
    tenant := dashIfEmpty(e.TenantID)
    scan := dashIfEmpty(e.ScanID)
    tool := dashIfEmpty(e.Tool)
    phase := dashIfEmpty(e.Phase)
    msg := e.Message
    if strings.TrimSpace(msg) == "" {
        msg = "-"
    }
    details := e.DetailsJSON
    if strings.TrimSpace(details) == "" {
        details = "{}"
    } else {
        // ensure valid json; if invalid, wrap as string field
        var js any
        if json.Unmarshal([]byte(details), &js) != nil {
            b, _ := json.Marshal(map[string]string{"raw": details})
            details = string(b)
        }
    }
    created := e.CreatedAt
    if created.IsZero() {
        created = time.Now()
    }
    _, err := r.db.ExecContext(ctx, q, tenant, scan, tool, phase, msg, details, created)
    return err
}

func (r *ScanErrorRepository) ListByScan(ctx context.Context, tenant string, scanID string, limit int) ([]*domain.ScanError, error) {
    if limit <= 0 { limit = 20 }
    const q = `
SELECT id, tenant_id, scan_id, tool, phase, message, details_json, created_at
FROM security_scan_errors
WHERE tenant_id = ? AND scan_id = ?
ORDER BY created_at DESC, id DESC
LIMIT ?;`
    rows, err := r.db.QueryContext(ctx, q, tenant, scanID, limit)
    if err != nil { return nil, err }
    defer rows.Close()
    var out []*domain.ScanError
    for rows.Next() {
        var e domain.ScanError
        var created time.Time
        if err := rows.Scan(&e.ID, &e.TenantID, &e.ScanID, &e.Tool, &e.Phase, &e.Message, &e.DetailsJSON, &created); err != nil {
            return nil, err
        }
        e.CreatedAt = created
        out = append(out, &e)
    }
    return out, rows.Err()
}

func dashIfEmpty(s string) string { if strings.TrimSpace(s) == "" { return "-" }; return s }

