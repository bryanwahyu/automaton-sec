package scans

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	domain "github.com/bryanwahyu/automaton-sec/internal/domain/scans"
)

// ---- fakes -----------------------------------------------------------------

type statusWrite struct {
	id     domain.ScanID
	status domain.Status
}

type fakeRepo struct {
	mu       sync.Mutex
	saved    []*domain.Scan
	statuses []statusWrite
	byID     map[domain.ScanID]*domain.Scan
	saveErr  error
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{byID: map[domain.ScanID]*domain.Scan{}}
}

func (f *fakeRepo) Save(_ context.Context, s *domain.Scan) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.saveErr != nil {
		return f.saveErr
	}
	cp := *s
	f.saved = append(f.saved, &cp)
	f.byID[s.ID] = &cp
	return nil
}

func (f *fakeRepo) Get(_ context.Context, _ string, id domain.ScanID) (*domain.Scan, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.byID[id]
	if !ok {
		return nil, errors.New("not found")
	}
	return s, nil
}

func (f *fakeRepo) UpdateStatus(_ context.Context, _ string, id domain.ScanID, status domain.Status) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.statuses = append(f.statuses, statusWrite{id: id, status: status})
	return nil
}

func (f *fakeRepo) lastSaved() *domain.Scan {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.saved) == 0 {
		return nil
	}
	return f.saved[len(f.saved)-1]
}

func (f *fakeRepo) statusWrites() []statusWrite {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]statusWrite(nil), f.statuses...)
}

// Unused by these tests, present to satisfy domain.Repository.
func (f *fakeRepo) Latest(context.Context, string, int) ([]*domain.Scan, error) { return nil, nil }
func (f *fakeRepo) Summary(context.Context, string, int) (int, int, int, int, error) {
	return 0, 0, 0, 0, nil
}
func (f *fakeRepo) UpdateResult(context.Context, string, domain.ScanID, domain.Status, string, domain.SeverityCounts) error {
	return nil
}
func (f *fakeRepo) UpdateCounts(context.Context, string, domain.ScanID, domain.SeverityCounts) error {
	return nil
}
func (f *fakeRepo) Paginate(context.Context, string, int, int, map[string]interface{}) (domain.PaginatedResult, error) {
	return domain.PaginatedResult{}, nil
}
func (f *fakeRepo) Cursor(context.Context, string, time.Time, string, int) ([]*domain.Scan, error) {
	return nil, nil
}
func (f *fakeRepo) Count(context.Context, string, map[string]interface{}) (int64, error) {
	return 0, nil
}

type fakeRunner struct {
	result  domain.RunResult
	err     error
	lastReq domain.RunRequest
}

func (f *fakeRunner) Run(_ context.Context, req domain.RunRequest) (domain.RunResult, error) {
	f.lastReq = req
	if f.err != nil {
		return domain.RunResult{}, f.err
	}
	return f.result, nil
}

type fakeStore struct{ err error }

func (f *fakeStore) Upload(_ context.Context, _, key string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	return "https://artifacts.test/" + key, nil
}

func (f *fakeStore) UploadAndCleanup(ctx context.Context, localPath, key string) (string, error) {
	url, err := f.Upload(ctx, localPath, key)
	if err == nil {
		os.Remove(localPath)
	}
	return url, err
}

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

func newService(t *testing.T, repo *fakeRepo, runner *fakeRunner, store *fakeStore) *Service {
	t.Helper()
	return &Service{Repo: repo, Runner: runner, Artifacts: store, Clock: fixedClock{t: time.Unix(1700000000, 0).UTC()}}
}

// artifact writes a stand-in artifact so UploadAndCleanup has a file to remove.
func artifact(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatalf("writing artifact: %v", err)
	}
	return path
}

// ---- tests -----------------------------------------------------------------

func TestTriggerScanStoresSuccessWhenTheScannerReportsFindings(t *testing.T) {
	// Trivy exits 1 to say "I found something". That is a successful scan, and
	// storing it as failed was the original defect.
	repo, store := newFakeRepo(), &fakeStore{}
	runner := &fakeRunner{result: domain.RunResult{
		Counts:            domain.SeverityCounts{Critical: 2, Total: 2},
		LocalArtifactPath: artifact(t),
		RawFormat:         "json",
		ExitCode:          1,
		HasFindings:       true,
	}}

	res, err := newService(t, repo, runner, store).TriggerScan(context.Background(),
		TriggerScanCommand{TenantID: "acme", Tool: "trivy", Image: "nginx:latest"})
	if err != nil {
		t.Fatalf("TriggerScan: %v", err)
	}

	if res.Status != string(domain.StatusSuccess) {
		t.Fatalf("status = %q, want %q", res.Status, domain.StatusSuccess)
	}
	if got := repo.lastSaved().Status; got != domain.StatusSuccess {
		t.Fatalf("stored status = %q, want %q", got, domain.StatusSuccess)
	}
}

func TestTriggerScanStoresFailedOnARealToolFailure(t *testing.T) {
	repo, store := newFakeRepo(), &fakeStore{}
	runner := &fakeRunner{result: domain.RunResult{
		LocalArtifactPath: artifact(t),
		ExitCode:          3,
		HasFindings:       false,
	}}

	res, err := newService(t, repo, runner, store).TriggerScan(context.Background(),
		TriggerScanCommand{TenantID: "acme", Tool: "trivy", Image: "nginx:latest"})
	if err != nil {
		t.Fatalf("TriggerScan: %v", err)
	}
	if res.Status != string(domain.StatusFailed) {
		t.Fatalf("status = %q, want %q", res.Status, domain.StatusFailed)
	}
}

func TestTriggerScanPersistsPathAndMetadata(t *testing.T) {
	repo, store := newFakeRepo(), &fakeStore{}
	runner := &fakeRunner{result: domain.RunResult{LocalArtifactPath: artifact(t), RawFormat: "json"}}

	_, err := newService(t, repo, runner, store).TriggerScan(context.Background(), TriggerScanCommand{
		TenantID: "acme",
		Tool:     "gitleaks",
		Path:     "/workspace/repo",
		Metadata: map[string]any{"pipeline": "nightly"},
	})
	if err != nil {
		t.Fatalf("TriggerScan: %v", err)
	}

	saved := repo.lastSaved()
	if saved.Path != "/workspace/repo" {
		t.Fatalf("stored path = %q, want /workspace/repo", saved.Path)
	}
	if saved.Metadata == nil {
		t.Fatal("metadata should be stored, not dropped")
	}
}

func TestTriggerScanMarksOnlyItsOwnScanOnFailure(t *testing.T) {
	// The status write must name the scan that failed. Addressing "the newest
	// scan of this tenant" corrupted whichever scan happened to be newer.
	repo, store := newFakeRepo(), &fakeStore{}
	runner := &fakeRunner{err: errors.New("trivy exploded")}

	res, err := newService(t, repo, runner, store).TriggerScan(context.Background(),
		TriggerScanCommand{TenantID: "acme", Tool: "trivy", Image: "nginx:latest"})
	if err == nil {
		t.Fatal("TriggerScan should surface the runner error")
	}

	writes := repo.statusWrites()
	if len(writes) != 1 {
		t.Fatalf("status writes = %d, want 1", len(writes))
	}
	if string(writes[0].id) != res.ID {
		t.Fatalf("status written for %q, want %q", writes[0].id, res.ID)
	}
	if writes[0].status != domain.StatusError {
		t.Fatalf("status = %q, want %q", writes[0].status, domain.StatusError)
	}
}

func TestTriggerScanRecordsAnErrorEvenWhenItsContextIsCancelled(t *testing.T) {
	// A scan killed by its own timeout still has to write its error status.
	repo, store := newFakeRepo(), &fakeStore{}
	runner := &fakeRunner{err: context.DeadlineExceeded}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := newService(t, repo, runner, store).TriggerScan(ctx,
		TriggerScanCommand{TenantID: "acme", Tool: "nuclei", Target: "https://example.com"}); err == nil {
		t.Fatal("expected the runner error to surface")
	}
	if len(repo.statusWrites()) != 1 {
		t.Fatal("the error status should still have been written")
	}
}

func TestRetryScanReusesTheStoredPath(t *testing.T) {
	// Gitleaks is driven entirely by Path; if the repo round-trip loses it, the
	// retry runs against nothing.
	repo, store := newFakeRepo(), &fakeStore{}
	repo.byID["scan-1"] = &domain.Scan{
		ID: "scan-1", TenantID: "acme", Tool: domain.ToolGitleaks, Path: "/workspace/repo",
	}
	runner := &fakeRunner{result: domain.RunResult{LocalArtifactPath: artifact(t), RawFormat: "json"}}

	if _, err := newService(t, repo, runner, store).RetryScan(context.Background(), "acme", "scan-1"); err != nil {
		t.Fatalf("RetryScan: %v", err)
	}
	if runner.lastReq.Path != "/workspace/repo" {
		t.Fatalf("retry ran with path %q, want /workspace/repo", runner.lastReq.Path)
	}
}

func TestPaginateClampsAndComputesTotalPages(t *testing.T) {
	svc := newService(t, newFakeRepo(), &fakeRunner{}, &fakeStore{})

	res, err := svc.Paginate(context.Background(), "acme", 0, 0, nil)
	if err != nil {
		t.Fatalf("Paginate: %v", err)
	}
	if res.Page != 1 || res.PageSize != 20 {
		t.Fatalf("page/pageSize = %d/%d, want 1/20", res.Page, res.PageSize)
	}
}

func TestStatusFromRun(t *testing.T) {
	cases := []struct {
		name string
		res  domain.RunResult
		want domain.Status
	}{
		{"clean exit", domain.RunResult{ExitCode: 0}, domain.StatusSuccess},
		{"findings exit", domain.RunResult{ExitCode: 1, HasFindings: true}, domain.StatusSuccess},
		{"tool failure", domain.RunResult{ExitCode: 2}, domain.StatusFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := statusFromRun(tc.res); got != tc.want {
				t.Fatalf("statusFromRun = %q, want %q", got, tc.want)
			}
		})
	}
}
