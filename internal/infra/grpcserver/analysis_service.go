package grpcserver

import (
	"context"
	"fmt"
	"log"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	secv1 "github.com/bryanwahyu/automaton-sec/gen/go/automaton/sec/v1"
	"github.com/bryanwahyu/automaton-sec/internal/apierr"
	anldom "github.com/bryanwahyu/automaton-sec/internal/domain/analyst"
	domain "github.com/bryanwahyu/automaton-sec/internal/domain/scans"
)

// analysisService implements AnalysisService over the shared Server state.
type analysisService struct {
	secv1.UnimplementedAnalysisServiceServer
	*Server
}

func (s *analysisService) AnalyzeScan(ctx context.Context, req *secv1.AnalyzeScanRequest) (*secv1.AnalyzeScanResponse, error) {
	tenant := req.GetTenant()
	scanID := req.GetScanId()
	if scanID == "" {
		return nil, toStatus(apierr.InvalidArgument(fmt.Errorf("scan_id is required")))
	}

	artifactURL, err := s.artifactURL(ctx, tenant, scanID)
	if err != nil {
		return nil, toStatus(err)
	}

	// The placeholder row is written before the response so the caller has an
	// analysis_id to poll with, exactly as the HTTP endpoint does.
	queued, err := s.aiSvc.QueueAnalysis(ctx, tenant, scanID, artifactURL)
	if err != nil {
		return nil, toStatus(err)
	}

	s.runAnalysis(tenant, scanID, queued.ID, artifactURL, "analyze")

	return &secv1.AnalyzeScanResponse{
		AnalysisId: string(queued.ID),
		Tenant:     tenant,
		ScanId:     scanID,
		QueuedAt:   timestamppb.New(queued.CreatedAt),
	}, nil
}

func (s *analysisService) RetryAnalysis(ctx context.Context, req *secv1.RetryAnalysisRequest) (*secv1.AnalyzeScanResponse, error) {
	tenant := req.GetTenant()
	scanID := req.GetScanId()
	if scanID == "" {
		return nil, toStatus(apierr.InvalidArgument(fmt.Errorf("scan_id is required")))
	}

	artifactURL, err := s.artifactURL(ctx, tenant, scanID)
	if err != nil {
		return nil, toStatus(err)
	}

	queuedAt := time.Now()
	var id anldom.AnalysisID
	if given := req.GetAnalysisId(); given != "" {
		// Retrying in place: mark the existing record so its state reflects
		// the request even before the analyzer answers.
		id = anldom.AnalysisID(given)
		s.aiSvc.UpdateAnalysisStatus(ctx, tenant, scanID, id, artifactURL, map[string]any{
			"status":      "retry_requested",
			"requestedAt": queuedAt,
		})
	} else {
		queued, err := s.aiSvc.QueueAnalysis(ctx, tenant, scanID, artifactURL)
		if err != nil {
			return nil, toStatus(err)
		}
		id = queued.ID
		queuedAt = queued.CreatedAt
	}

	s.runAnalysis(tenant, scanID, id, artifactURL, "retry")

	return &secv1.AnalyzeScanResponse{
		AnalysisId: string(id),
		Tenant:     tenant,
		ScanId:     scanID,
		QueuedAt:   timestamppb.New(queuedAt),
	}, nil
}

func (s *analysisService) ListAnalyses(ctx context.Context, req *secv1.ListAnalysesRequest) (*secv1.ListAnalysesResponse, error) {
	list, err := s.aiSvc.ListAnalyses(ctx, req.GetTenant(), clampPage(req.GetPage()), clampPageSize(req.GetPageSize()))
	if err != nil {
		return nil, toStatus(err)
	}
	out := &secv1.ListAnalysesResponse{Analyses: make([]*secv1.Analysis, 0, len(list))}
	for _, a := range list {
		out.Analyses = append(out.Analyses, analysisToProto(a))
	}
	return out, nil
}

// artifactURL resolves the report an analysis will read. A scan with no
// artifact cannot be analyzed, and that is the caller's mistake rather than a
// server failure — usually the scan is still running.
func (s *analysisService) artifactURL(ctx context.Context, tenant, scanID string) (string, error) {
	scan, err := s.scansSvc.Get(ctx, tenant, domain.ScanID(scanID))
	if err != nil {
		return "", err
	}
	if scan == nil {
		return "", apierr.ErrNotFound
	}
	if scan.ArtifactURL == "" {
		return "", apierr.InvalidArgument(
			fmt.Errorf("scan %s has no artifact to analyze yet (status=%s)", scanID, scan.Status))
	}
	return scan.ArtifactURL, nil
}

// runAnalysis starts the analyzer in the background.
//
// The context is deliberately not the request's: the work must outlive the RPC
// that started it, which returns as soon as the record is queued.
func (s *analysisService) runAnalysis(tenant, scanID string, id anldom.AnalysisID, artifactURL, phase string) {
	go func() {
		if _, err := s.aiSvc.AnalyzeAndStoreWithID(context.Background(), tenant, scanID, id, artifactURL); err != nil {
			log.Printf("grpc ai %s failed tenant=%s scan_id=%s analysis_id=%s: %v",
				phase, tenant, scanID, id, err)
		}
	}()
}
