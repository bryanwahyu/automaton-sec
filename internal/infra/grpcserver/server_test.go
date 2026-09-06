package grpcserver

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	secv1 "github.com/bryanwahyu/automaton-sec/gen/go/automaton/sec/v1"
	"github.com/bryanwahyu/automaton-sec/internal/application"
	appscans "github.com/bryanwahyu/automaton-sec/internal/application/scans"
	domain "github.com/bryanwahyu/automaton-sec/internal/domain/scans"
)

const testAPIKey = "api-key-1"

type harness struct {
	repo  *stubRepo
	scans secv1.ScanServiceClient
	conn  *grpc.ClientConn
}

// newHarness starts a server on an in-memory listener, so the tests exercise
// the real interceptor chain and the real codec without binding a port.
func newHarness(t *testing.T, deps func(*Deps)) *harness {
	t.Helper()

	repo := newStubRepo()
	d := Deps{
		ScansSvc: &appscans.Service{
			Repo:      repo,
			Runner:    stubRunner{},
			Artifacts: stubStore{},
			Clock:     application.SystemClock{},
		},
		Pool: application.NewPool(1, time.Minute),
		// Loopback targets are allowed so these tests never touch DNS.
		Policy:        domain.TargetPolicy{AllowPrivateTargets: true},
		Auth:          AuthConfig{APIKeys: []string{testAPIKey}},
		WatchInterval: 10 * time.Millisecond,
	}
	if deps != nil {
		deps(&d)
	}

	lis := bufconn.Listen(1024 * 1024)
	srv := New(d)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	return &harness{repo: repo, scans: secv1.NewScanServiceClient(conn), conn: conn}
}

// authCtx returns a context carrying a valid API key.
func authCtx(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+testAPIKey), cancel
}

func TestUnaryCallNeedsAPIKey(t *testing.T) {
	h := newHarness(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := h.scans.GetScan(ctx, &secv1.GetScanRequest{Tenant: "acme", Id: "whatever"})
	if got := status.Code(err); got != codes.Unauthenticated {
		t.Fatalf("want Unauthenticated without a key, got %v (%v)", got, err)
	}
}

func TestUnaryCallRejectsWrongAPIKey(t *testing.T) {
	h := newHarness(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer not-the-key")

	_, err := h.scans.GetScan(ctx, &secv1.GetScanRequest{Tenant: "acme", Id: "whatever"})
	if got := status.Code(err); got != codes.Unauthenticated {
		t.Fatalf("want Unauthenticated for a wrong key, got %v (%v)", got, err)
	}
}

func TestMalformedTenantIsInvalidArgument(t *testing.T) {
	h := newHarness(t, nil)
	ctx, cancel := authCtx(t)
	defer cancel()

	_, err := h.scans.GetScan(ctx, &secv1.GetScanRequest{Tenant: "not a tenant!", Id: "x"})
	if got := status.Code(err); got != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument for a malformed tenant, got %v (%v)", got, err)
	}
}

func TestGetUnknownScanIsNotFound(t *testing.T) {
	h := newHarness(t, nil)
	ctx, cancel := authCtx(t)
	defer cancel()

	_, err := h.scans.GetScan(ctx, &secv1.GetScanRequest{Tenant: "acme", Id: "missing"})
	if got := status.Code(err); got != codes.NotFound {
		t.Fatalf("want NotFound for an unknown scan, got %v (%v)", got, err)
	}
}

func TestTriggerScanRejectsUnusableTarget(t *testing.T) {
	h := newHarness(t, nil)
	ctx, cancel := authCtx(t)
	defer cancel()

	// An unset tool cannot be dispatched, so the policy must reject it before
	// anything is queued.
	_, err := h.scans.TriggerScan(ctx, &secv1.TriggerScanRequest{Tenant: "acme"})
	if got := status.Code(err); got != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument for an unset tool, got %v (%v)", got, err)
	}
}

func TestTriggerScanReturnsScanID(t *testing.T) {
	h := newHarness(t, nil)
	ctx, cancel := authCtx(t)
	defer cancel()

	res, err := h.scans.TriggerScan(ctx, &secv1.TriggerScanRequest{
		Tenant: "acme",
		Tool:   secv1.Tool_TOOL_NUCLEI,
		Target: "http://127.0.0.1/",
	})
	if err != nil {
		t.Fatalf("TriggerScan: %v", err)
	}
	if res.GetScanId() == "" {
		t.Fatal("TriggerScan returned no scan id; the caller would have no handle on its own scan")
	}
	if res.GetQueuedAt() == nil {
		t.Error("TriggerScan returned no queued_at")
	}
	if res.GetTool() != secv1.Tool_TOOL_NUCLEI {
		t.Errorf("tool = %v, want TOOL_NUCLEI", res.GetTool())
	}
}

func TestTriggerScanIsBusyWhenPoolSaturated(t *testing.T) {
	release := make(chan struct{})
	pool := application.NewPool(1, time.Minute)
	// Occupy the only slot, so the next submission cannot be queued.
	if err := pool.Submit(func(context.Context) { <-release }); err != nil {
		t.Fatalf("seeding the pool: %v", err)
	}
	defer close(release)

	h := newHarness(t, func(d *Deps) { d.Pool = pool })
	ctx, cancel := authCtx(t)
	defer cancel()

	_, err := h.scans.TriggerScan(ctx, &secv1.TriggerScanRequest{
		Tenant: "acme",
		Tool:   secv1.Tool_TOOL_NUCLEI,
		Target: "http://127.0.0.1/",
	})
	if got := status.Code(err); got != codes.ResourceExhausted {
		t.Fatalf("want ResourceExhausted from a saturated pool, got %v (%v)", got, err)
	}
}

func TestWatchScanStreamsUntilTerminal(t *testing.T) {
	h := newHarness(t, nil)
	ctx, cancel := authCtx(t)
	defer cancel()

	h.repo.put(&domain.Scan{
		ID: "scan-1", TenantID: "acme", Tool: domain.ToolTrivy,
		Status: domain.StatusRunning, TriggeredAt: time.Now(),
	})

	stream, err := h.scans.WatchScan(ctx, &secv1.WatchScanRequest{Tenant: "acme", Id: "scan-1"})
	if err != nil {
		t.Fatalf("WatchScan: %v", err)
	}

	// The first message is the current state, so a client that connects late
	// still learns where the scan stands.
	first, err := stream.Recv()
	if err != nil {
		t.Fatalf("first Recv: %v", err)
	}
	if first.GetStatus() != secv1.Status_STATUS_RUNNING {
		t.Fatalf("first status = %v, want STATUS_RUNNING", first.GetStatus())
	}

	h.repo.put(&domain.Scan{
		ID: "scan-1", TenantID: "acme", Tool: domain.ToolTrivy,
		Status: domain.StatusSuccess, TriggeredAt: first.GetTriggeredAt().AsTime(),
		ArtifactURL: "https://artifacts.test/acme/trivy/report.json",
		Counts:      domain.SeverityCounts{Critical: 1, Total: 1},
	})

	final, err := stream.Recv()
	if err != nil {
		t.Fatalf("second Recv: %v", err)
	}
	if final.GetStatus() != secv1.Status_STATUS_SUCCESS {
		t.Fatalf("final status = %v, want STATUS_SUCCESS", final.GetStatus())
	}
	if final.GetCounts().GetCritical() != 1 {
		t.Errorf("critical = %d, want 1", final.GetCounts().GetCritical())
	}

	// A terminal scan closes the stream rather than leaving the client hanging.
	if _, err := stream.Recv(); err == nil {
		t.Fatal("stream stayed open after the scan reached a terminal status")
	}
}

func TestWatchScanEndsImmediatelyForFinishedScan(t *testing.T) {
	h := newHarness(t, nil)
	ctx, cancel := authCtx(t)
	defer cancel()

	h.repo.put(&domain.Scan{
		ID: "done-1", TenantID: "acme", Tool: domain.ToolTrivy,
		Status: domain.StatusSuccess, TriggeredAt: time.Now(),
	})

	stream, err := h.scans.WatchScan(ctx, &secv1.WatchScanRequest{Tenant: "acme", Id: "done-1"})
	if err != nil {
		t.Fatalf("WatchScan: %v", err)
	}
	got, err := stream.Recv()
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if got.GetStatus() != secv1.Status_STATUS_SUCCESS {
		t.Fatalf("status = %v, want STATUS_SUCCESS", got.GetStatus())
	}
	if _, err := stream.Recv(); err == nil {
		t.Fatal("want the stream closed after one message for an already finished scan")
	}
}

func TestWatchScanNeedsAPIKey(t *testing.T) {
	h := newHarness(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := h.scans.WatchScan(ctx, &secv1.WatchScanRequest{Tenant: "acme", Id: "scan-1"})
	if err == nil {
		_, err = stream.Recv()
	}
	if got := status.Code(err); got != codes.Unauthenticated {
		t.Fatalf("want Unauthenticated on an unauthenticated stream, got %v (%v)", got, err)
	}
}

func TestWatchScanRejectsMalformedTenant(t *testing.T) {
	h := newHarness(t, nil)
	ctx, cancel := authCtx(t)
	defer cancel()

	// Tenant validation on a stream can only run once the first message has
	// been received, so this proves the check is not skipped for streams.
	stream, err := h.scans.WatchScan(ctx, &secv1.WatchScanRequest{Tenant: "bad tenant!", Id: "x"})
	if err == nil {
		_, err = stream.Recv()
	}
	if got := status.Code(err); got != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument for a malformed tenant on a stream, got %v (%v)", got, err)
	}
}

func TestGetSummaryMapsRepositoryCounters(t *testing.T) {
	h := newHarness(t, nil)
	ctx, cancel := authCtx(t)
	defer cancel()

	got, err := h.scans.GetSummary(ctx, &secv1.GetSummaryRequest{Tenant: "acme", Days: 7})
	if err != nil {
		t.Fatalf("GetSummary: %v", err)
	}
	// The stub repository reports total=4, critical=1, high=2, medium=3.
	if got.GetTotalScans() != 4 || got.GetCritical() != 1 || got.GetHigh() != 2 || got.GetMedium() != 3 {
		t.Fatalf("summary = %+v, want 4/1/2/3", got)
	}
}

func TestHealthServiceIsServing(t *testing.T) {
	h := newHarness(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Health is deliberately reachable without a credential: a probe must not
	// need one, and it exposes no scan data.
	res, err := healthpb.NewHealthClient(h.conn).Check(ctx, &healthpb.HealthCheckRequest{})
	if err != nil {
		t.Fatalf("Health.Check: %v", err)
	}
	if res.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("health = %v, want SERVING", res.GetStatus())
	}
}
