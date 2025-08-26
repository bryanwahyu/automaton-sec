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

// TriggerScan jalankan scanner → upload artifact → simpan ke repo
func (s *Service) TriggerScan(ctx context.Context, cmd TriggerScanCommand) (TriggerScanResult, error) {
	now := s.Clock.Now()
	uniqueID := uuid.New().String()
	id := fmt.Sprintf("%s-%s", uniqueID, cmd.Tool)

	// jalankan runner
	res, err := s.Runner.Run(ctx, domain.RunRequest{
		Tool:   domain.Tool(cmd.Tool),
		Mode:   cmd.Mode,
		Image:  cmd.Image,
		Path:   cmd.Path,
		Target: cmd.Target,
	})
	if err != nil {
		return TriggerScanResult{}, err
	}

	// upload artifact and clean up automatically
	key := fmt.Sprintf("%s/%s/%s", cmd.TenantID, cmd.Tool, filepath.Base(res.LocalArtifactPath))
	url, err := s.Artifacts.UploadAndCleanup(ctx, res.LocalArtifactPath, key)
	if err != nil {
		// Clean up the temporary file even if upload fails
		os.Remove(res.LocalArtifactPath)
		return TriggerScanResult{}, err
	}

	// buat entity
	scan := &domain.Scan{
		ID:          domain.ScanID(id),
		TenantID:    cmd.TenantID,
		TriggeredAt: now,
		Tool:        domain.Tool(cmd.Tool),
		Target:      cmd.Target,
		Image:       cmd.Image,
		Path:        cmd.Path,
		Status:      statusFromExit(res.ExitCode),
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
		return TriggerScanResult{}, err
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


// Latest ambil N scan terakhir
func (s *Service) Latest(ctx context.Context, tenant string, limit int) ([]*domain.Scan, error) {
	return s.Repo.Latest(ctx, tenant, limit)
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

// helper
func statusFromExit(code int) domain.Status {
	if code == 0 {
		return domain.StatusSuccess
	}
	return domain.StatusFailed
}
