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

// TriggerScanUntilDone → jalanin scan dengan context.Background()
// cocok dipanggil dari goroutine di router supaya gak kena context canceled
func (s *Service) TriggerScanUntilDone(cmd TriggerScanCommand) (TriggerScanResult, error) {
    return s.TriggerScan(context.Background(), cmd)
}

// UpdateStatus → untuk update status scan di repo (misalnya "queued", "running", "failed")
func (s *Service) UpdateStatus(tenant string, status string) error {
	// Implementasi sederhana: update ke repo
	// Bisa diperluas untuk logging / audit
	return s.Repo.UpdateStatus(context.Background(), tenant, domain.Status(status))
}

// MarkDone → update status scan jadi done/success + simpan hasil
func (s *Service) MarkDone(tenant string, res TriggerScanResult) error {
	// kamu bisa langsung update status di repo
	return s.Repo.UpdateResult(
		context.Background(),
		tenant,
		domain.ScanID(res.ID),
		domain.StatusSuccess,
		res.ArtifactURL,
		res.Counts,
	)
}

// TriggerScan jalankan scanner → upload artifact → simpan ke repo
func (s *Service) TriggerScan(ctx context.Context, cmd TriggerScanCommand) (TriggerScanResult, error) {
    now := s.Clock.Now()
    uniqueID := uuid.New().String()
    id := fmt.Sprintf("%s-%s", uniqueID, cmd.Tool)

    // Create an initial scan row so we always have an ID to reference
    initial := &domain.Scan{
        ID:          domain.ScanID(id),
        TenantID:    cmd.TenantID,
        TriggeredAt: now,
        Tool:        domain.Tool(cmd.Tool),
        Target:      cmd.Target,
        Image:       cmd.Image,
        Path:        cmd.Path,
        Status:      domain.Status("running"),
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
        _ = s.Repo.UpdateStatus(context.Background(), cmd.TenantID, domain.StatusError)
        return TriggerScanResult{ID: id, Status: string(domain.StatusError)}, err
    }

    // upload artifact and clean up automatically
    key := fmt.Sprintf("%s/%s/%s", cmd.TenantID, cmd.Tool, filepath.Base(res.LocalArtifactPath))
    url, err := s.Artifacts.UploadAndCleanup(ctx, res.LocalArtifactPath, key)
    if err != nil {
        // Clean up the temporary file even if upload fails
        os.Remove(res.LocalArtifactPath)
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
    _ = s.Repo.UpdateStatus(context.Background(), tenant, domain.Status("running"))

    // jalankan runner sekali tanpa retry
    res, err := s.Runner.Run(ctx, domain.RunRequest{
        Tool:   existing.Tool,
        Mode:   "", // mode tidak disimpan di entity; runner saat ini tidak bergantung pada mode
        Image:  existing.Image,
        Path:   existing.Path,
        Target: existing.Target,
    })
    if err != nil {
        _ = s.Repo.UpdateStatus(context.Background(), tenant, domain.StatusError)
        return TriggerScanResult{ID: string(existing.ID), Status: string(domain.StatusError)}, err
    }

    // upload artifact
    key := fmt.Sprintf("%s/%s/%s", tenant, existing.Tool, filepath.Base(res.LocalArtifactPath))
    url, uerr := s.Artifacts.UploadAndCleanup(ctx, res.LocalArtifactPath, key)
    if uerr != nil {
        os.Remove(res.LocalArtifactPath)
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
        Status:      statusFromExit(res.ExitCode),
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

 
