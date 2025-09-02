package ai

import (
    "context"
    "time"

    domai "github.com/bryanwahyu/automaton-sec/internal/domain/ai"
    analyst "github.com/bryanwahyu/automaton-sec/internal/domain/analyst"
    scans "github.com/bryanwahyu/automaton-sec/internal/domain/scans"
    "github.com/google/uuid"
)

type Service struct {
    client       domai.Client
    analystRepo  analyst.Repository
    scansRepo    scans.Repository // used to record a scan count entry for AI analyses
}

func NewService(client domai.Client) *Service {
    return &Service{client: client}
}

// WithRepos injects repositories needed for persistence
func (s *Service) WithRepos(ar analyst.Repository, sr scans.Repository) *Service {
    s.analystRepo = ar
    s.scansRepo = sr
    return s
}

func (s *Service) Analyze(ctx context.Context, fileURL string) (string, error) {
    return s.client.Analyze(ctx, fileURL)
}

// AnalyzeAndStore runs the AI analysis, saves it to security_analyze, and optionally updates counts on an existing security_scans row.
// It does NOT create a new security_scans record.
func (s *Service) AnalyzeAndStore(ctx context.Context, tenant, scanID string, counts *scans.SeverityCounts, fileURL string) (*analyst.Analysis, error) {
    result, err := s.client.Analyze(ctx, fileURL)
    if err != nil {
        return nil, err
    }

    a := &analyst.Analysis{
        ID:        analyst.AnalysisID(uuid.New().String()),
        TenantID:  tenant,
        ScanID:    scanID,
        FileURL:   fileURL,
        Result:    result,
        CreatedAt: time.Now(),
    }
    if s.analystRepo != nil {
        if err := s.analystRepo.Save(ctx, a); err != nil {
            return nil, err
        }
    }

    // If a scanID and counts are provided, update only counts on that scan (no new row)
    if s.scansRepo != nil && scanID != "" && counts != nil {
        _ = s.scansRepo.UpdateCounts(ctx, tenant, scans.ScanID(scanID), *counts)
    }

    return a, nil
}

// ListAnalyses returns paginated analysis list for a tenant
func (s *Service) ListAnalyses(ctx context.Context, tenant string, page, pageSize int) ([]*analyst.Analysis, error) {
    if s.analystRepo == nil {
        return nil, nil
    }
    return s.analystRepo.Paginate(ctx, tenant, page, pageSize)
}
