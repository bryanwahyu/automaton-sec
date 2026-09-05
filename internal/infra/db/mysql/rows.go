package mysql

import (
	"database/sql"
	"encoding/json"

	domain "github.com/bryanwahyu/automaton-sec/internal/domain/scans"
)

// rowScanner is satisfied by both *sql.Row and *sql.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

// scanInto reads one security_scans row into s.
//
// path and metadata are read through NullString: they were added after the
// original schema, so rows written before the migration hold NULL.
func scanInto(row rowScanner, s *domain.Scan) error {
	var crit, hi, med, lo, tot int
	var path, metadata sql.NullString

	if err := row.Scan(
		&s.ID, &s.TenantID, &s.TriggeredAt, &s.Tool, &s.Target, &s.Image, &path, &s.Status,
		&crit, &hi, &med, &lo, &tot,
		&s.ArtifactURL, &s.RawFormat, &s.DurationMS,
		&s.Source, &s.CommitSHA, &s.Branch, &metadata,
	); err != nil {
		return err
	}

	s.Path = path.String
	s.Counts = domain.SeverityCounts{Critical: crit, High: hi, Medium: med, Low: lo, Total: tot}
	if metadata.Valid && metadata.String != "" {
		var m any
		if err := json.Unmarshal([]byte(metadata.String), &m); err == nil {
			s.Metadata = m
		}
	}
	return nil
}

// marshalMetadata encodes free-form scan metadata for storage, writing SQL NULL
// rather than the string "null" when there is nothing to store.
func marshalMetadata(v any) (any, error) {
	if v == nil {
		return nil, nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	if string(b) == "null" {
		return nil, nil
	}
	return string(b), nil
}
