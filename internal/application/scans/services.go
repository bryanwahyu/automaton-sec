package scans

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"

	domain "github.com/bryanwahyu/automaton-sec/internal/domain/scans"
)

// Service implements use-cases untuk Scan
// Service is designed to be used concurrently and is thread-safe
type Service struct {
	Repo      domain.Repository
	Runner    domain.Runner
	Artifacts domain.ArtifactStore
	Clock     Clock
}

// Clock abstraction supaya gampang ditest
type Clock interface {
	Now() time.Time
}

type SystemClock struct{}

func (SystemClock) Now() time.Time { return time.Now() }

//
// ==== USE CASES ====
//

// Command untuk trigger scan
type TriggerScanCommand struct {
	// ScanID lets the caller decide the id up front so it can be handed back
	// in the 202 response. Empty means the service generates one.
	ScanID    string
	TenantID  string
	Tool      string
	Mode      string
	Image     string
	Path      string
	Target    string
	Source    string
	CommitSHA string
	Branch    string
	Metadata  any
}

type TriggerScanResult struct {
	ID          string                `json:"id"`
	Status      string                `json:"status"`
	Counts      domain.SeverityCounts `json:"counts"`
	ArtifactURL string                `json:"artifact_url"`
	RawFormat   string                `json:"raw_format"`
	DurationMS  int64                 `json:"duration_ms"`
}

// UpdateStatus sets the status of one specific scan.
//
// It takes a scan ID on purpose: the previous signature updated "the newest
// scan of this tenant", which silently corrupted the status of an unrelated
// scan whenever two ran concurrently.
func (s *Service) UpdateStatus(ctx context.Context, tenant string, id domain.ScanID, status domain.Status) error {
	return s.Repo.UpdateStatus(ctx, tenant, id, status)
}

// MarkDone persists the final result of a finished scan.
func (s *Service) MarkDone(ctx context.Context, tenant string, res TriggerScanResult) error {
	return s.Repo.UpdateResult(
		ctx,
		tenant,
		domain.ScanID(res.ID),
		domain.Status(res.Status),
		res.ArtifactURL,
		res.Counts,
	)
}

// TriggerScan jalankan scanner → upload artifact → simpan ke repo
func (s *Service) TriggerScan(ctx context.Context, cmd TriggerScanCommand) (TriggerScanResult, error) {
	now := s.Clock.Now()
	id := cmd.ScanID
	if id == "" {
		id = NewScanID(cmd.Tool)
	}

	// Create an initial scan row so we always have an ID to reference
	initial := &domain.Scan{
		ID:          domain.ScanID(id),
		TenantID:    cmd.TenantID,
		TriggeredAt: now,
		Tool:        domain.Tool(cmd.Tool),
		Target:      cmd.Target,
		Image:       cmd.Image,
		Path:        cmd.Path,
		Status:      domain.StatusRunning,
		Counts:      domain.SeverityCounts{},
		ArtifactURL: "",
		RawFormat:   "",
		DurationMS:  0,
		Source:      cmd.Source,
		CommitSHA:   cmd.CommitSHA,
		Branch:      cmd.Branch,
		Metadata:    cmd.Metadata,
	}
	if err := s.Repo.Save(ctx, initial); err != nil {
		// If we can't save initial row, return with the generated ID for caller logging
		return TriggerScanResult{ID: id, Status: string(domain.StatusError)}, err
	}

	// jalankan runner sekali, tanpa retry
	res, err := s.Runner.Run(ctx, domain.RunRequest{
		Tool:   domain.Tool(cmd.Tool),
		Mode:   cmd.Mode,
		Image:  cmd.Image,
		Path:   cmd.Path,
		Target: cmd.Target,
	})
	if err != nil {
		s.markError(ctx, cmd.TenantID, domain.ScanID(id))
		return TriggerScanResult{ID: id, Status: string(domain.StatusError)}, err
	}

	// upload artifact and clean up automatically
	key := fmt.Sprintf("%s/%s/%s", cmd.TenantID, cmd.Tool, filepath.Base(res.LocalArtifactPath))
	url, err := s.Artifacts.UploadAndCleanup(ctx, res.LocalArtifactPath, key)
	if err != nil {
		// Clean up the temporary file even if upload fails
		os.Remove(res.LocalArtifactPath)
		s.markError(ctx, cmd.TenantID, domain.ScanID(id))
		return TriggerScanResult{ID: id, Status: string(domain.StatusError)}, err
	}

	// update entity with final results
	scan := &domain.Scan{
		ID:          domain.ScanID(id),
		TenantID:    cmd.TenantID,
		TriggeredAt: now,
		Tool:        domain.Tool(cmd.Tool),
		Target:      cmd.Target,
		Image:       cmd.Image,
		Path:        cmd.Path,
		Status:      statusFromRun(res),
		Counts:      res.Counts,
		ArtifactURL: url,
		RawFormat:   res.RawFormat,
		DurationMS:  res.DurationMS,
		Source:      cmd.Source,
		CommitSHA:   cmd.CommitSHA,
		Branch:      cmd.Branch,
		Metadata:    cmd.Metadata,
	}

	if err := s.Repo.Save(ctx, scan); err != nil {
		return TriggerScanResult{ID: id, Status: string(scan.Status)}, err
	}

	return TriggerScanResult{
		ID:          string(scan.ID),
		Status:      string(scan.Status),
		Counts:      scan.Counts,
		ArtifactURL: scan.ArtifactURL,
		RawFormat:   scan.RawFormat,
		DurationMS:  scan.DurationMS,
	}, nil
}

// RetryScan: jalankan ulang sebuah scan yang sudah ada (biasanya yang status error/failed)
func (s *Service) RetryScan(ctx context.Context, tenant string, id domain.ScanID) (TriggerScanResult, error) {
	// Ambil scan yang mau diretry
	existing, err := s.Repo.Get(ctx, tenant, id)
	if err != nil {
		return TriggerScanResult{}, err
	}
	if existing == nil {
		return TriggerScanResult{}, fmt.Errorf("scan not found: %s", id)
	}

	// tandai running
	_ = s.Repo.UpdateStatus(ctx, tenant, id, domain.StatusRunning)

	// jalankan runner sekali tanpa retry
	res, err := s.Runner.Run(ctx, domain.RunRequest{
		Tool:   existing.Tool,
		Mode:   "", // mode tidak disimpan di entity; runner saat ini tidak bergantung pada mode
		Image:  existing.Image,
		Path:   existing.Path,
		Target: existing.Target,
	})
	if err != nil {
		s.markError(ctx, tenant, existing.ID)
		return TriggerScanResult{ID: string(existing.ID), Status: string(domain.StatusError)}, err
	}

	// upload artifact
	key := fmt.Sprintf("%s/%s/%s", tenant, existing.Tool, filepath.Base(res.LocalArtifactPath))
	url, uerr := s.Artifacts.UploadAndCleanup(ctx, res.LocalArtifactPath, key)
	if uerr != nil {
		os.Remove(res.LocalArtifactPath)
		s.markError(ctx, tenant, existing.ID)
		return TriggerScanResult{ID: string(existing.ID), Status: string(domain.StatusError)}, uerr
	}

	// simpan hasil retry (Save akan upsert kolom-kolom hasil)
	updated := &domain.Scan{
		ID:          existing.ID,
		TenantID:    tenant,
		TriggeredAt: existing.TriggeredAt,
		Tool:        existing.Tool,
		Target:      existing.Target,
		Image:       existing.Image,
		Path:        existing.Path,
		Status:      statusFromRun(res),
		Counts:      res.Counts,
		ArtifactURL: url,
		RawFormat:   res.RawFormat,
		DurationMS:  res.DurationMS,
		Source:      existing.Source,
		CommitSHA:   existing.CommitSHA,
		Branch:      existing.Branch,
		Metadata:    existing.Metadata,
	}
	if err := s.Repo.Save(ctx, updated); err != nil {
		return TriggerScanResult{ID: string(existing.ID), Status: string(updated.Status)}, err
	}

	return TriggerScanResult{
		ID:          string(updated.ID),
		Status:      string(updated.Status),
		Counts:      updated.Counts,
		ArtifactURL: updated.ArtifactURL,
		RawFormat:   updated.RawFormat,
		DurationMS:  updated.DurationMS,
	}, nil
}

// NewScanID builds the id format the rest of the system expects: a UUID with
// the tool name appended.
func NewScanID(tool string) string {
	return fmt.Sprintf("%s-%s", uuid.New().String(), tool)
}

// Latest ambil N scan terakhir
func (s *Service) Latest(ctx context.Context, tenant string, limit int) ([]*domain.Scan, error) {
	return s.Repo.Latest(ctx, tenant, limit)
}

// Paginate returns paginated scans with filters
func (s *Service) Paginate(ctx context.Context, tenant string, page, pageSize int, filters map[string]interface{}) (domain.PaginatedResult, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 20
	}

	// Get total count for pagination
	total, err := s.Repo.Count(ctx, tenant, filters)
	if err != nil {
		return domain.PaginatedResult{}, err
	}

	// Calculate total pages
	totalPages := (int(total) + pageSize - 1) / pageSize

	// Get paginated data
	data, err := s.Repo.Paginate(ctx, tenant, page, pageSize, filters)
	if err != nil {
		return domain.PaginatedResult{}, err
	}

	// Construct PaginatedResult with pagination metadata
	return domain.PaginatedResult{
		Data:       data.Data,
		Page:       page,
		PageSize:   pageSize,
		Total:      total,
		TotalPages: totalPages,
	}, nil
}

// Cursor mengambil data dengan cursor-based pagination
func (s *Service) Cursor(ctx context.Context, tenant string, cursorTime time.Time, cursorID string, limit int) ([]*domain.Scan, error) {
	return s.Repo.Cursor(ctx, tenant, cursorTime, cursorID, limit)
}

// Get ambil 1 scan by id
func (s *Service) Get(ctx context.Context, tenant string, id domain.ScanID) (*domain.Scan, error) {
	return s.Repo.Get(ctx, tenant, id)
}

// Summary rekap hasil scan N hari terakhir
func (s *Service) Summary(ctx context.Context, tenant string, sinceDays int) (map[string]any, error) {
	total, critical, high, medium, err := s.Repo.Summary(ctx, tenant, sinceDays)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"total_scans": total,
		"critical":    critical,
		"high":        high,
		"medium":      medium,
	}, nil
}

// statusFromRun maps a completed run to a stored status.
//
// A scanner that exits non-zero purely because it found something has still
// succeeded; the runner reports that as HasFindings. Only a genuine tool
// failure becomes StatusFailed.
func statusFromRun(res domain.RunResult) domain.Status {
	if res.ExitCode == 0 || res.HasFindings {
		return domain.StatusSuccess
	}
	return domain.StatusFailed
}

// markError records a failure without inheriting the cancelled scan context —
// otherwise a timed-out scan could never write its own error status.
func (s *Service) markError(ctx context.Context, tenant string, id domain.ScanID) {
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_ = s.Repo.UpdateStatus(writeCtx, tenant, id, domain.StatusError)
}
