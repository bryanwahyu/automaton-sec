package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"strings"
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
	// Ensure non-nullable string fields have safe defaults and numbers fall back to 0
	tenant := stringOrDash(s.TenantID)
	tool := stringOrDash(string(s.Tool))
	status := stringOrDash(string(s.Status))
	triggered := s.TriggeredAt
	if triggered.IsZero() {
		triggered = time.Now()
	}
	// Numeric fields (ints) are value types and already default to 0

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
func (r *ScanRepository) Paginate(ctx context.Context, tenant string, page, pageSize int, filters map[string]interface{}) (domain.PaginatedResult, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 20
	}
	offset := (page - 1) * pageSize

	query := `
SELECT id, tenant_id, triggered_at, tool, target, image, status,
       critical, high, medium, low, findings_total,
       artifact_url, raw_format, duration_ms, source, commit_sha, branch
FROM security_scans
WHERE tenant_id=?`

	args := []interface{}{tenant}

	// Add filters to the query
	if filters != nil {
		for key, value := range filters {
			switch key {
			case "tool":
				query += " AND tool = ?"
				args = append(args, value)
			case "status":
				query += " AND status = ?"
				args = append(args, value)
			case "target":
				// Use LIKE with wildcards - sanitize input to prevent SQL injection
				query += " AND target LIKE ?"
				searchTerm := value.(string)
				// Escape LIKE special characters
				searchTerm = escapeLikePattern(searchTerm)
				args = append(args, "%"+searchTerm+"%")
			case "branch":
				query += " AND branch = ?"
				args = append(args, value)
			}
		}
	}

	query += "\n LIMIT ? OFFSET ?"
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

	// Get total count for pagination
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

// UpdateCounts updates only the counts columns for a specific scan id
func (r *ScanRepository) UpdateCounts(ctx context.Context, tenant string, id domain.ScanID, counts domain.SeverityCounts) error {
	const q = `
UPDATE security_scans
SET critical = ?,
    high = ?,
    medium = ?,
    low = ?,
    findings_total = ?
WHERE tenant_id = ? AND id = ?;`
	_, err := r.db.ExecContext(ctx, q,
		counts.Critical, counts.High, counts.Medium, counts.Low, counts.Total,
		tenant, id,
	)
	return err
}

// Count returns the total number of records matching the given filters
func (r *ScanRepository) Count(ctx context.Context, tenant string, filters map[string]interface{}) (int64, error) {
	query := "SELECT COUNT(*) FROM security_scans WHERE tenant_id = ?"
	args := []interface{}{tenant}

	// Add filters to the query
	if filters != nil {
		for key, value := range filters {
			switch key {
			case "tool":
				query += " AND tool = ?"
				args = append(args, value)
			case "status":
				query += " AND status = ?"
				args = append(args, value)
			case "target":
				// Use LIKE with wildcards - sanitize input to prevent SQL injection
				query += " AND target LIKE ?"
				searchTerm := value.(string)
				// Escape LIKE special characters
				searchTerm = escapeLikePattern(searchTerm)
				args = append(args, "%"+searchTerm+"%")
			case "branch":
				query += " AND branch = ?"
				args = append(args, value)
			}
		}
	}

	var count int64
	err := r.db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		return 0, err
	}

	return count, nil
}

// escapeLikePattern escapes special characters in LIKE patterns to prevent SQL injection
func escapeLikePattern(s string) string {
	// Escape backslash first, then other LIKE special characters
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "%", "\\%")
	s = strings.ReplaceAll(s, "_", "\\_")
	return s
}
