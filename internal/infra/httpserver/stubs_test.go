package httpserver

import (
	"context"
	"os"
	"time"

	domain "github.com/bryanwahyu/automaton-sec/internal/domain/scans"
)

// stubRepo is an in-memory domain.Repository that records nothing beyond what
// these handler tests need.
type stubRepo struct{}

func (stubRepo) Save(context.Context, *domain.Scan) error { return nil }
func (stubRepo) Get(_ context.Context, tenant string, id domain.ScanID) (*domain.Scan, error) {
	return &domain.Scan{ID: id, TenantID: tenant, Tool: domain.ToolNuclei, Target: "http://127.0.0.1/"}, nil
}
func (stubRepo) Latest(context.Context, string, int) ([]*domain.Scan, error) { return nil, nil }
func (stubRepo) Summary(context.Context, string, int) (int, int, int, int, error) {
	return 0, 0, 0, 0, nil
}
func (stubRepo) UpdateStatus(context.Context, string, domain.ScanID, domain.Status) error { return nil }
func (stubRepo) UpdateResult(context.Context, string, domain.ScanID, domain.Status, string, domain.SeverityCounts) error {
	return nil
}
func (stubRepo) UpdateCounts(context.Context, string, domain.ScanID, domain.SeverityCounts) error {
	return nil
}
func (stubRepo) Paginate(context.Context, string, int, int, map[string]interface{}) (domain.PaginatedResult, error) {
	return domain.PaginatedResult{}, nil
}
func (stubRepo) Cursor(context.Context, string, time.Time, string, int) ([]*domain.Scan, error) {
	return nil, nil
}
func (stubRepo) Count(context.Context, string, map[string]interface{}) (int64, error) { return 0, nil }

// stubRunner writes an empty artifact so the upload step has a file.
type stubRunner struct{}

func (stubRunner) Run(context.Context, domain.RunRequest) (domain.RunResult, error) {
	f, err := os.CreateTemp("", "stub-artifact-*.json")
	if err != nil {
		return domain.RunResult{}, err
	}
	defer f.Close()
	if _, err := f.WriteString("{}"); err != nil {
		return domain.RunResult{}, err
	}
	return domain.RunResult{LocalArtifactPath: f.Name(), RawFormat: "json"}, nil
}

type stubStore struct{}

func (stubStore) Upload(_ context.Context, _, key string) (string, error) {
	return "https://artifacts.test/" + key, nil
}
func (s stubStore) UploadAndCleanup(ctx context.Context, localPath, key string) (string, error) {
	url, err := s.Upload(ctx, localPath, key)
	os.Remove(localPath)
	return url, err
}
