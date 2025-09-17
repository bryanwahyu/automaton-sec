package postgres

import (
    "context"
    "database/sql"
    "fmt"
    "math"
    "regexp"
    "time"

    domain "github.com/bryanwahyu/automaton-sec/internal/domain/scans"
)

type ScanRepository struct { db *sql.DB }

func NewScanRepository(db *sql.DB) *ScanRepository { return &ScanRepository{db: db} }

// Save insert/update Scan record
func (r *ScanRepository) Save(ctx context.Context, s *domain.Scan) error {
    const q = `
INSERT INTO security_scans
(id, tenant_id, triggered_at, tool, target, image, status,
 critical, high, medium, low, findings_total,
 artifact_url, raw_format, duration_ms, source, commit_sha, branch)
VALUES ($1,$2,$3,$4,$5,$6,$7,
        $8,$9,$10,$11,$12,
        $13,$14,$15,$16,$17,$18)
ON CONFLICT (id) DO UPDATE SET
 status = EXCLUDED.status,
 critical = EXCLUDED.critical,
 high = EXCLUDED.high,
 medium = EXCLUDED.medium,
 low = EXCLUDED.low,
 findings_total = EXCLUDED.findings_total,
 artifact_url = EXCLUDED.artifact_url,
 raw_format = EXCLUDED.raw_format,
 duration_ms = EXCLUDED.duration_ms;`

    tenant := stringOrDash(s.TenantID)
    tool := stringOrDash(string(s.Tool))
    status := stringOrDash(string(s.Status))
    triggered := s.TriggeredAt
    if triggered.IsZero() { triggered = time.Now() }

    _, err := r.db.ExecContext(ctx, q,
        s.ID, tenant, triggered, tool, s.Target, s.Image, status,
        s.Counts.Critical, s.Counts.High, s.Counts.Medium, s.Counts.Low, s.Counts.Total,
        s.ArtifactURL, s.RawFormat, s.DurationMS,
        s.Source, s.CommitSHA, s.Branch,
    )
    return err
}

// Get by ID + Tenant
func (r *ScanRepository) Get(ctx context.Context, tenant string, id domain.ScanID) (*domain.Scan, error) {
    const q = `
SELECT id, tenant_id, triggered_at, tool, target, image, status,
       critical, high, medium, low, findings_total,
       artifact_url, raw_format, duration_ms, source, commit_sha, branch
FROM security_scans
WHERE tenant_id=$1 AND id=$2
LIMIT 1;`
    row := r.db.QueryRowContext(ctx, q, tenant, id)
    var s domain.Scan
    var crit, hi, med, lo, tot int
    if err := row.Scan(
        &s.ID, &s.TenantID, &s.TriggeredAt, &s.Tool, &s.Target, &s.Image, &s.Status,
        &crit, &hi, &med, &lo, &tot,
        &s.ArtifactURL, &s.RawFormat, &s.DurationMS,
        &s.Source, &s.CommitSHA, &s.Branch,
    ); err != nil {
        return nil, err
    }
    s.Counts = domain.SeverityCounts{Critical: crit, High: hi, Medium: med, Low: lo, Total: tot}
    return &s, nil
}

// Latest scans per tenant
func (r *ScanRepository) Latest(ctx context.Context, tenant string, limit int) ([]*domain.Scan, error) {
    if limit <= 0 { limit = 20 }
    const q = `
SELECT id, tenant_id, triggered_at, tool, target, image, status,
       critical, high, medium, low, findings_total,
       artifact_url, raw_format, duration_ms, source, commit_sha, branch
FROM security_scans
WHERE tenant_id=$1 ORDER BY triggered_at DESC
LIMIT $2;`
    rows, err := r.db.QueryContext(ctx, q, tenant, limit)
    if err != nil { return nil, err }
    defer rows.Close()
    var out []*domain.Scan
    for rows.Next() {
        var s domain.Scan
        var crit, hi, med, lo, tot int
        if err := rows.Scan(
            &s.ID, &s.TenantID, &s.TriggeredAt, &s.Tool, &s.Target, &s.Image, &s.Status,
            &crit, &hi, &med, &lo, &tot,
            &s.ArtifactURL, &s.RawFormat, &s.DurationMS,
            &s.Source, &s.CommitSHA, &s.Branch,
        ); err != nil { return nil, err }
        s.Counts = domain.SeverityCounts{Critical: crit, High: hi, Medium: med, Low: lo, Total: tot}
        out = append(out, &s)
    }
    return out, rows.Err()
}

// Summary counts scan results since N days
func (r *ScanRepository) Summary(ctx context.Context, tenant string, sinceDays int) (int, int, int, int, error) {
    if sinceDays <= 0 { sinceDays = 7 }
    cut := time.Now().AddDate(0, 0, -sinceDays)
    const q = `
SELECT COUNT(*) AS total_scans,
       COALESCE(SUM(critical),0) AS critical,
       COALESCE(SUM(high),0)     AS high,
       COALESCE(SUM(medium),0)   AS medium
FROM security_scans
WHERE tenant_id=$1 AND triggered_at >= $2;`
    var t, c, h, m int
    if err := r.db.QueryRowContext(ctx, q, tenant, cut).Scan(&t, &c, &h, &m); err != nil {
        return 0, 0, 0, 0, err
    }
    return t, c, h, m, nil
}

// Paginate with offset + limit (classic pagination)
func (r *ScanRepository) Paginate(ctx context.Context, tenant string, page, pageSize int, filters map[string]interface{}) (domain.PaginatedResult, error) {
    if page <= 0 { page = 1 }
    if pageSize <= 0 { pageSize = 20 }
    offset := (page - 1) * pageSize

    query := `
SELECT id, tenant_id, triggered_at, tool, target, image, status,
       critical, high, medium, low, findings_total,
       artifact_url, raw_format, duration_ms, source, commit_sha, branch
FROM security_scans
WHERE tenant_id=$1`

    args := []interface{}{tenant}
    next := 2

    if filters != nil {
        for key, value := range filters {
            switch key {
            case "tool":
                query += fmt.Sprintf(" AND tool = $%d", next)
                args = append(args, value)
                next++
            case "status":
                query += fmt.Sprintf(" AND status = $%d", next)
                args = append(args, value)
                next++
            case "target":
                // Use LIKE and a regex on separators (., /)
                // Build patterns in Go and pass as params
                term := value.(string)
                likeMiddle := "% " + term + " %"
                likeEnd := "% " + term
                likeStart := term + " %"
                // regex: (^|\.|/)term($|\.|/)
                escaped := regexp.QuoteMeta(term)
                regex := fmt.Sprintf("(^|\\.|/)%s($|\\.|/)", escaped)
                query += fmt.Sprintf(" AND (target LIKE $%d OR target LIKE $%d OR target LIKE $%d OR target ~ $%d)", next, next+1, next+2, next+3)
                args = append(args, likeMiddle, likeEnd, likeStart, regex)
                next += 4
            case "branch":
                query += fmt.Sprintf(" AND branch = $%d", next)
                args = append(args, value)
                next++
            }
        }
    }

    query += fmt.Sprintf("\n LIMIT $%d OFFSET $%d", next, next+1)
    args = append(args, pageSize, offset)

    rows, err := r.db.QueryContext(ctx, query, args...)
    if err != nil {
        return domain.PaginatedResult{}, fmt.Errorf("querying scans: %w", err)
    }
    defer rows.Close()

    var scans []*domain.Scan
    for rows.Next() {
        var s domain.Scan
        var crit, hi, med, lo, tot int
        if err := rows.Scan(
            &s.ID, &s.TenantID, &s.TriggeredAt, &s.Tool, &s.Target, &s.Image, &s.Status,
            &crit, &hi, &med, &lo, &tot,
            &s.ArtifactURL, &s.RawFormat, &s.DurationMS,
            &s.Source, &s.CommitSHA, &s.Branch,
        ); err != nil {
            return domain.PaginatedResult{}, fmt.Errorf("scanning row: %w", err)
        }
        s.Counts = domain.SeverityCounts{Critical: crit, High: hi, Medium: med, Low: lo, Total: tot}
        scans = append(scans, &s)
    }
    if err = rows.Err(); err != nil {
        return domain.PaginatedResult{}, fmt.Errorf("iterating rows: %w", err)
    }

    total, err := r.Count(ctx, tenant, filters)
    if err != nil {
        return domain.PaginatedResult{}, fmt.Errorf("getting total count: %w", err)
    }

    return domain.PaginatedResult{
        Data:       scans,
        Page:       page,
        PageSize:   pageSize,
        Total:      total,
        TotalPages: int(math.Ceil(float64(total) / float64(pageSize))),
    }, nil
}

// UpdateStatus update last scan status for tenant (use CTE)
func (r *ScanRepository) UpdateStatus(ctx context.Context, tenant string, status domain.Status) error {
    const q = `
WITH latest AS (
  SELECT id FROM security_scans
  WHERE tenant_id = $2
  ORDER BY triggered_at DESC, id DESC
  LIMIT 1
)
UPDATE security_scans s
SET status = $1
FROM latest
WHERE s.id = latest.id;`
    _, err := r.db.ExecContext(ctx, q, status, tenant)
    return err
}

// UpdateResult update hasil scan
func (r *ScanRepository) UpdateResult(ctx context.Context, tenant string, id domain.ScanID, status domain.Status, artifactURL string, counts domain.SeverityCounts) error {
    const q = `
UPDATE security_scans
SET status = $1,
    critical = $2,
    high = $3,
    medium = $4,
    low = $5,
    findings_total = $6,
    artifact_url = $7
WHERE tenant_id = $8 AND id = $9;`
    _, err := r.db.ExecContext(ctx, q,
        status,
        counts.Critical, counts.High, counts.Medium, counts.Low, counts.Total,
        artifactURL,
        tenant, id,
    )
    return err
}

// Cursor-based pagination (after cursorTime, cursorID)
func (r *ScanRepository) Cursor(ctx context.Context, tenant string, cursorTime time.Time, cursorID string, pageSize int) ([]*domain.Scan, error) {
    if pageSize <= 0 { pageSize = 20 }
    const q = `
SELECT id, tenant_id, triggered_at, tool, target, image, status,
       critical, high, medium, low, findings_total,
       artifact_url, raw_format, duration_ms, source, commit_sha, branch
FROM security_scans
WHERE tenant_id=$1
  AND (triggered_at < $2 OR (triggered_at = $3 AND id < $4))
ORDER BY triggered_at DESC, id DESC
LIMIT $5;`
    rows, err := r.db.QueryContext(ctx, q, tenant, cursorTime, cursorTime, cursorID, pageSize)
    if err != nil { return nil, err }
    defer rows.Close()
    var out []*domain.Scan
    for rows.Next() {
        var s domain.Scan
        var crit, hi, med, lo, tot int
        if err := rows.Scan(
            &s.ID, &s.TenantID, &s.TriggeredAt, &s.Tool, &s.Target, &s.Image, &s.Status,
            &crit, &hi, &med, &lo, &tot,
            &s.ArtifactURL, &s.RawFormat, &s.DurationMS,
            &s.Source, &s.CommitSHA, &s.Branch,
        ); err != nil { return nil, err }
        s.Counts = domain.SeverityCounts{Critical: crit, High: hi, Medium: med, Low: lo, Total: tot}
        out = append(out, &s)
    }
    return out, rows.Err()
}

// UpdateCounts updates only the counts columns for a specific scan id
func (r *ScanRepository) UpdateCounts(ctx context.Context, tenant string, id domain.ScanID, counts domain.SeverityCounts) error {
    const q = `
UPDATE security_scans
SET critical = $1,
    high = $2,
    medium = $3,
    low = $4,
    findings_total = $5
WHERE tenant_id = $6 AND id = $7;`
    _, err := r.db.ExecContext(ctx, q,
        counts.Critical, counts.High, counts.Medium, counts.Low, counts.Total,
        tenant, id,
    )
    return err
}

// Count returns the total number of records matching the given filters
func (r *ScanRepository) Count(ctx context.Context, tenant string, filters map[string]interface{}) (int64, error) {
    query := "SELECT COUNT(*) FROM security_scans WHERE tenant_id = $1"
    args := []interface{}{tenant}
    next := 2

    if filters != nil {
        for key, value := range filters {
            switch key {
            case "tool":
                query += fmt.Sprintf(" AND tool = $%d", next)
                args = append(args, value)
                next++
            case "status":
                query += fmt.Sprintf(" AND status = $%d", next)
                args = append(args, value)
                next++
            case "target":
                term := value.(string)
                likeMiddle := "% " + term + " %"
                likeEnd := "% " + term
                likeStart := term + " %"
                escaped := regexp.QuoteMeta(term)
                regex := fmt.Sprintf("(^|\\.|/)\n%s($|\\.|/)", escaped)
                // Note: the newline in the format above is not intended; correct it below
                regex = fmt.Sprintf("(^|\\.|/)%s($|\\.|/)", escaped)
                query += fmt.Sprintf(" AND (target LIKE $%d OR target LIKE $%d OR target LIKE $%d OR target ~ $%d)", next, next+1, next+2, next+3)
                args = append(args, likeMiddle, likeEnd, likeStart, regex)
                next += 4
            case "branch":
                query += fmt.Sprintf(" AND branch = $%d", next)
                args = append(args, value)
                next++
            }
        }
    }

    var count int64
    if err := r.db.QueryRowContext(ctx, query, args...).Scan(&count); err != nil {
        return 0, err
    }
    return count, nil
}

