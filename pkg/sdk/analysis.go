package sdk

import (
	"context"

	secv1 "github.com/bryanwahyu/automaton-sec/gen/go/automaton/sec/v1"
)

// AnalyzeScan queues AI analysis of a finished scan's artifact and returns the
// id of the analysis record. The analysis itself runs in the background; read
// it back with LatestAnalysis or ListAnalyses.
func (c *Client) AnalyzeScan(ctx context.Context, tenant, scanID string) (*secv1.AnalyzeScanResponse, error) {
	return do(ctx, c, func(ctx context.Context) (*secv1.AnalyzeScanResponse, error) {
		return c.analyses.AnalyzeScan(ctx, &secv1.AnalyzeScanRequest{Tenant: tenant, ScanId: scanID})
	})
}

// RetryAnalysis re-runs analysis immediately, ignoring any scheduled backoff.
// An empty analysisID creates a new record instead of retrying one in place.
func (c *Client) RetryAnalysis(ctx context.Context, tenant, scanID, analysisID string) (*secv1.AnalyzeScanResponse, error) {
	return do(ctx, c, func(ctx context.Context) (*secv1.AnalyzeScanResponse, error) {
		return c.analyses.RetryAnalysis(ctx, &secv1.RetryAnalysisRequest{
			Tenant: tenant, ScanId: scanID, AnalysisId: analysisID,
		})
	})
}

// ListAnalyses pages through a tenant's analyses, newest first.
func (c *Client) ListAnalyses(ctx context.Context, tenant string, page, pageSize int32) (*secv1.ListAnalysesResponse, error) {
	return do(ctx, c, func(ctx context.Context) (*secv1.ListAnalysesResponse, error) {
		return c.analyses.ListAnalyses(ctx, &secv1.ListAnalysesRequest{
			Tenant: tenant, Page: page, PageSize: pageSize,
		})
	})
}
