package grpcserver

import (
	"context"
	"os"
	"sync"
	"time"

	domain "github.com/bryanwahyu/automaton-sec/internal/domain/scans"
)

// stubRepo is an in-memory domain.Repository. It stores real rows because the
// gRPC tests care about what comes back out — WatchScan in particular only has
// a story to tell if a row can change while it is being watched.
type stubRepo struct {
	mu    sync.Mutex
	scans map[domain.ScanID]*domain.Scan
	// getErr, when set, fails every Get. It exists to exercise error mapping.
	getErr error
}

func newStubRepo() *stubRepo {
	return &stubRepo{scans: map[domain.ScanID]*domain.Scan{}}
}

func (r *stubRepo) put(s *domain.Scan) {
	r.mu.Lock()
	defer r.mu.Unlock()
	copied := *s
	r.scans[s.ID] = &copied
}

func (r *stubRepo) Save(_ context.Context, s *domain.Scan) error {
	r.put(s)
	return nil
}

func (r *stubRepo) Get(_ context.Context, tenant string, id domain.ScanID) (*domain.Scan, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.getErr != nil {
		return nil, r.getErr
	}
	s, ok := r.scans[id]
	if !ok || s.TenantID != tenant {
		return nil, nil
	}
	copied := *s
	return &copied, nil
}

func (r *stubRepo) Latest(_ context.Context, tenant string, limit int) ([]*domain.Scan, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []*domain.Scan
	for _, s := range r.scans {
		if s.TenantID == tenant && len(out) < limit {
			copied := *s
			out = append(out, &copied)
		}
	}
	return out, nil
}

func (r *stubRepo) Summary(context.Context, string, int) (int, int, int, int, error) {
	return 4, 1, 2, 3, nil
}

func (r *stubRepo) UpdateStatus(_ context.Context, _ string, id domain.ScanID, status domain.Status) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.scans[id]; ok {
		s.Status = status
	}
	return nil
}

func (r *stubRepo) UpdateResult(_ context.Context, _ string, id domain.ScanID, status domain.Status, url string, counts domain.SeverityCounts) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.scans[id]; ok {
		s.Status = status
		s.ArtifactURL = url
		s.Counts = counts
	}
	return nil
}

func (r *stubRepo) UpdateCounts(_ context.Context, _ string, id domain.ScanID, counts domain.SeverityCounts) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.scans[id]; ok {
		s.Counts = counts
	}
	return nil
}

func (r *stubRepo) Paginate(_ context.Context, tenant string, page, pageSize int, _ map[string]any) (domain.PaginatedResult, error) {
	data, _ := r.Latest(context.Background(), tenant, pageSize)
	return domain.PaginatedResult{Data: data, Page: page, PageSize: pageSize}, nil
}

func (r *stubRepo) Cursor(_ context.Context, tenant string, _ time.Time, _ string, pageSize int) ([]*domain.Scan, error) {
	return r.Latest(context.Background(), tenant, pageSize)
}

func (r *stubRepo) Count(_ context.Context, tenant string, _ map[string]any) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var n int64
	for _, s := range r.scans {
		if s.TenantID == tenant {
			n++
		}
	}
	return n, nil
}

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
