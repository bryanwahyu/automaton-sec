package mysql

import (
	"context"
	"database/sql"
	"time"

	domain "github.com/bryanwahyu/automaton-sec/internal/domain/scans"
)

type ScanRepository struct {
	db *sql.DB
}

func NewScanRepository(db *sql.DB) *ScanRepository {
	return &ScanRepository{db: db}
}


// Save insert/update Scan record
func (r *ScanRepository) Save(ctx context.Context, s *domain.Scan) error {
	const q = `
INSERT INTO security_scans
(id, tenant_id, triggered_at, tool, target, image, status,
 critical, high, medium, low, findings_total,
 artifact_url, raw_format, duration_ms, source, commit_sha, branch)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON DUPLICATE KEY UPDATE
 status=VALUES(status),
 critical=VALUES(critical), high=VALUES(high), medium=VALUES(medium), low=VALUES(low),
 findings_total=VALUES(findings_total),
 artifact_url=VALUES(artifact_url), raw_format=VALUES(raw_format), duration_ms=VALUES(duration_ms);
`
	_, err := r.db.ExecContext(ctx, q,
		s.ID, s.TenantID, s.TriggeredAt, s.Tool, s.Target, s.Image, s.Status,
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
WHERE tenant_id=? AND id=? LIMIT 1;
`
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
	if limit <= 0 {
		limit = 20
	}
	const q = `
SELECT id, tenant_id, triggered_at, tool, target, image, status,
       critical, high, medium, low, findings_total,
       artifact_url, raw_format, duration_ms, source, commit_sha, branch
FROM security_scans
WHERE tenant_id=? ORDER BY triggered_at DESC LIMIT ?;
`
	rows, err := r.db.QueryContext(ctx, q, tenant, limit)
	if err != nil {
		return nil, err
	}
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
		); err != nil {
			return nil, err
		}
		s.Counts = domain.SeverityCounts{Critical: crit, High: hi, Medium: med, Low: lo, Total: tot}
		out = append(out, &s)
	}
	return out, rows.Err()
}

// Summary counts scan results since N days
func (r *ScanRepository) Summary(ctx context.Context, tenant string, sinceDays int) (int, int, int, int, error) {
	if sinceDays <= 0 {
		sinceDays = 7
	}
	cut := time.Now().AddDate(0, 0, -sinceDays)

	const q = `
SELECT COUNT(*) AS total_scans,
       COALESCE(SUM(critical),0) AS critical,
       COALESCE(SUM(high),0)     AS high,
       COALESCE(SUM(medium),0)   AS medium
FROM security_scans
WHERE tenant_id=? AND triggered_at >= ?;
`
	var t, c, h, m int
	if err := r.db.QueryRowContext(ctx, q, tenant, cut).Scan(&t, &c, &h, &m); err != nil {
		return 0, 0, 0, 0, err
	}
	return t, c, h, m, nil
}

// Paginate with offset + limit (classic pagination)
func (r *ScanRepository) Paginate(ctx context.Context, tenant string, page, pageSize int) ([]*domain.Scan, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 20
	}
	offset := (page - 1) * pageSize

	const q = `
SELECT id, tenant_id, triggered_at, tool, target, image, status,
       critical, high, medium, low, findings_total,
       artifact_url, raw_format, duration_ms, source, commit_sha, branch
FROM security_scans
WHERE tenant_id=?
ORDER BY triggered_at DESC, id DESC
LIMIT ? OFFSET ?;
`
	rows, err := r.db.QueryContext(ctx, q, tenant, pageSize, offset)
	if err != nil {
		return nil, err
	}
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
		); err != nil {
			return nil, err
		}
		s.Counts = domain.SeverityCounts{Critical: crit, High: hi, Medium: med, Low: lo, Total: tot}
		out = append(out, &s)
	}
	return out, rows.Err()
}
// UpdateStatus hanya update kolom status
func (r *ScanRepository) UpdateStatus(ctx context.Context, tenant string, status domain.Status) error {
	const q = `
UPDATE security_scans
SET status = ?
WHERE tenant_id = ?
ORDER BY triggered_at DESC
LIMIT 1;`
	_, err := r.db.ExecContext(ctx, q, status, tenant)
	return err
}

// UpdateResult update hasil scan terakhir (status, artifact_url, counts)
func (r *ScanRepository) UpdateResult(ctx context.Context, tenant string, id domain.ScanID, status domain.Status, artifactURL string, counts domain.SeverityCounts) error {
	const q = `
UPDATE security_scans
SET status = ?,
    critical = ?,
    high = ?,
    medium = ?,
    low = ?,
    findings_total = ?,
    artifact_url = ?
WHERE tenant_id = ? AND id = ?;`
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
	if pageSize <= 0 {
		pageSize = 20
	}

	const q = `
SELECT id, tenant_id, triggered_at, tool, target, image, status,
       critical, high, medium, low, findings_total,
       artifact_url, raw_format, duration_ms, source, commit_sha, branch
FROM security_scans
WHERE tenant_id=? 
  AND (triggered_at < ? OR (triggered_at = ? AND id < ?))
ORDER BY triggered_at DESC, id DESC
LIMIT ?;
`
	rows, err := r.db.QueryContext(ctx, q, tenant, cursorTime, cursorTime, cursorID, pageSize)
	if err != nil {
		return nil, err
	}
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
		); err != nil {
			return nil, err
		}
		s.Counts = domain.SeverityCounts{Critical: crit, High: hi, Medium: med, Low: lo, Total: tot}
		out = append(out, &s)
	}
	return out, rows.Err()
}
