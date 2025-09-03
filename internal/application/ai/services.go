package ai

import (
    "context"
    "encoding/json"
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

    // If counts not provided, try to extract from AI result JSON per schema
    if counts == nil {
        if cc := extractCountsFromAIResult(result); cc != nil {
            counts = cc
        }
    }
    // If a scanID available and counts present, update only counts on that scan (no new row)
    if s.scansRepo != nil && scanID != "" && counts != nil {
        _ = s.scansRepo.UpdateCounts(ctx, tenant, scans.ScanID(scanID), *counts)
    }

    return a, nil
}

// QueueAnalysis creates a placeholder analysis record immediately with status=queued
// and returns the created analysis containing its ID and queued timestamp.
// This allows the HTTP layer to return quickly while work continues in background.
func (s *Service) QueueAnalysis(ctx context.Context, tenant, scanID, fileURL string) (*analyst.Analysis, error) {
    if s.analystRepo == nil {
        // no repo configured; nothing to persist
        return &analyst.Analysis{
            ID:        analyst.AnalysisID(uuid.New().String()),
            TenantID:  tenant,
            ScanID:    scanID,
            FileURL:   fileURL,
            Result:    `{"status":"queued"}`,
            CreatedAt: time.Now(),
        }, nil
    }

    a := &analyst.Analysis{
        ID:        analyst.AnalysisID(uuid.New().String()),
        TenantID:  tenant,
        ScanID:    scanID,
        FileURL:   fileURL,
        Result:    `{"status":"queued"}`,
        CreatedAt: time.Now(),
    }
    if err := s.analystRepo.Save(ctx, a); err != nil {
        return nil, err
    }
    return a, nil
}

// AnalyzeAndStoreWithID performs analysis and upserts into security_analyze using a fixed ID.
// If a queued record was created earlier with the same ID, the created_at remains intact
// because the repo does not update that column on duplicate.
func (s *Service) AnalyzeAndStoreWithID(ctx context.Context, tenant, scanID string, id analyst.AnalysisID, fileURL string) (*analyst.Analysis, error) {
    result, err := s.client.Analyze(ctx, fileURL)
    if err != nil {
        return nil, err
    }

    a := &analyst.Analysis{
        ID:        id,
        TenantID:  tenant,
        ScanID:    scanID,
        FileURL:   fileURL,
        Result:    result,
        CreatedAt: time.Now(), // will be ignored on duplicate update
    }
    if s.analystRepo != nil {
        if err := s.analystRepo.Save(ctx, a); err != nil {
            return nil, err
        }
    }

    // extract counts from AI result and update the related scan if possible
    if cc := extractCountsFromAIResult(result); cc != nil && s.scansRepo != nil && scanID != "" {
        _ = s.scansRepo.UpdateCounts(ctx, tenant, scans.ScanID(scanID), *cc)
    }
    return a, nil
}

// extractCountsFromAIResult attempts to parse a counts object from the AI JSON.
func extractCountsFromAIResult(result string) *scans.SeverityCounts {
    var payload struct {
        Counts struct {
            Critical int `json:"critical"`
            High     int `json:"high"`
            Medium   int `json:"medium"`
            Low      int `json:"low"`
            Total    int `json:"total"`
        } `json:"counts"`
    }
    if err := json.Unmarshal([]byte(result), &payload); err != nil {
        return nil
    }
    // If all zeros and total zero, treat as empty
    if payload.Counts.Critical == 0 && payload.Counts.High == 0 && payload.Counts.Medium == 0 && payload.Counts.Low == 0 && payload.Counts.Total == 0 {
        return nil
    }
    // Ensure total consistency
    sum := payload.Counts.Critical + payload.Counts.High + payload.Counts.Medium + payload.Counts.Low
    if payload.Counts.Total == 0 {
        payload.Counts.Total = sum
    }
    return &scans.SeverityCounts{
        Critical: payload.Counts.Critical,
        High:     payload.Counts.High,
        Medium:   payload.Counts.Medium,
        Low:      payload.Counts.Low,
        Total:    payload.Counts.Total,
    }
}

// ListAnalyses returns paginated analysis list for a tenant
func (s *Service) ListAnalyses(ctx context.Context, tenant string, page, pageSize int) ([]*analyst.Analysis, error) {
    if s.analystRepo == nil {
        return nil, nil
    }
    return s.analystRepo.Paginate(ctx, tenant, page, pageSize)
}
