package sdk_test

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/timestamppb"

	secv1 "github.com/bryanwahyu/automaton-sec/gen/go/automaton/sec/v1"
	"github.com/bryanwahyu/automaton-sec/pkg/sdk"
)

// fakeService is a hand-written ScanService, so these tests exercise the SDK's
// own behaviour — auth metadata, retry, the WaitForScan fallback — rather than
// the server's.
type fakeService struct {
	secv1.UnimplementedScanServiceServer

	mu sync.Mutex
	// keys records the authorization metadata each call arrived with.
	keys []string
	// getCalls counts GetScan calls, so a polling fallback is visible.
	getCalls int
	// getFailures is how many times GetScan fails before succeeding.
	getFailures int
	// getCode is the status returned while failing.
	getCode codes.Code
	// scans answers GetScan; the last entry is repeated once exhausted.
	scans []*secv1.Scan
	// watchErr, when set, fails WatchScan so the fallback path runs.
	watchErr error
	// watchMessages is streamed by WatchScan when it does not fail.
	watchMessages []*secv1.Scan
}

func (f *fakeService) recordAuth(ctx context.Context) {
	md, _ := metadata.FromIncomingContext(ctx)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keys = append(f.keys, firstOrEmpty(md.Get("authorization")))
}

func firstOrEmpty(v []string) string {
	if len(v) == 0 {
		return ""
	}
	return v[0]
}

func (f *fakeService) GetScan(ctx context.Context, _ *secv1.GetScanRequest) (*secv1.Scan, error) {
	f.recordAuth(ctx)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.getCalls++
	if f.getFailures > 0 {
		f.getFailures--
		return nil, status.Error(f.getCode, "induced failure")
	}
	if len(f.scans) == 0 {
		return nil, status.Error(codes.NotFound, "not found")
	}
	idx := f.getCalls - 1
	if idx >= len(f.scans) {
		idx = len(f.scans) - 1
	}
	return f.scans[idx], nil
}

func (f *fakeService) WatchScan(_ *secv1.WatchScanRequest, stream secv1.ScanService_WatchScanServer) error {
	f.recordAuth(stream.Context())
	if f.watchErr != nil {
		return f.watchErr
	}
	for _, s := range f.watchMessages {
		if err := stream.Send(s); err != nil {
			return err
		}
	}
	return nil
}

func startFake(t *testing.T, svc *fakeService, opts ...sdk.Option) *sdk.Client {
	t.Helper()

	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	secv1.RegisterScanServiceServer(srv, svc)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	opts = append(opts, sdk.WithDialOptions(
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
	))
	c, err := sdk.New("passthrough:///bufnet", opts...)
	if err != nil {
		t.Fatalf("sdk.New: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func runningScan() *secv1.Scan {
	return &secv1.Scan{
		Id: "scan-1", Tenant: "acme", Status: secv1.Status_STATUS_RUNNING,
		TriggeredAt: timestamppb.New(time.Now()),
	}
}

func finishedScan() *secv1.Scan {
	return &secv1.Scan{
		Id: "scan-1", Tenant: "acme", Status: secv1.Status_STATUS_SUCCESS,
		ArtifactUrl: "https://artifacts.test/acme/trivy/report.json",
		Counts:      &secv1.SeverityCounts{Critical: 2, Total: 2},
		TriggeredAt: timestamppb.New(time.Now()),
	}
}

func TestAPIKeyIsSentOnEveryCall(t *testing.T) {
	svc := &fakeService{scans: []*secv1.Scan{finishedScan()}}
	c := startFake(t, svc, sdk.WithAPIKey("k1"))

	if _, err := c.GetScan(context.Background(), "acme", "scan-1"); err != nil {
		t.Fatalf("GetScan: %v", err)
	}
	svc.mu.Lock()
	defer svc.mu.Unlock()
	if len(svc.keys) != 1 || svc.keys[0] != "Bearer k1" {
		t.Fatalf("authorization metadata = %v, want [\"Bearer k1\"]", svc.keys)
	}
}

func TestRetriesUnavailableThenSucceeds(t *testing.T) {
	svc := &fakeService{
		scans:       []*secv1.Scan{finishedScan()},
		getFailures: 2,
		getCode:     codes.Unavailable,
	}
	c := startFake(t, svc, sdk.WithRetryPolicy(sdk.RetryPolicy{
		MaxAttempts: 4, BaseDelay: time.Millisecond, MaxDelay: 5 * time.Millisecond,
	}))

	if _, err := c.GetScan(context.Background(), "acme", "scan-1"); err != nil {
		t.Fatalf("GetScan should have survived two Unavailable responses: %v", err)
	}
	svc.mu.Lock()
	defer svc.mu.Unlock()
	if svc.getCalls != 3 {
		t.Fatalf("GetScan called %d times, want 3 (two failures then a success)", svc.getCalls)
	}
}

func TestDoesNotRetryInvalidArgument(t *testing.T) {
	svc := &fakeService{
		scans:       []*secv1.Scan{finishedScan()},
		getFailures: 1,
		getCode:     codes.InvalidArgument,
	}
	c := startFake(t, svc, sdk.WithRetryPolicy(sdk.RetryPolicy{
		MaxAttempts: 4, BaseDelay: time.Millisecond, MaxDelay: 5 * time.Millisecond,
	}))

	_, err := c.GetScan(context.Background(), "acme", "scan-1")
	if got := status.Code(err); got != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument returned as-is, got %v (%v)", got, err)
	}
	svc.mu.Lock()
	defer svc.mu.Unlock()
	// Retrying a rejected argument would fail identically every time; one call
	// is the whole point of the policy.
	if svc.getCalls != 1 {
		t.Fatalf("GetScan called %d times, want 1", svc.getCalls)
	}
}

func TestWaitForScanUsesTheStream(t *testing.T) {
	svc := &fakeService{watchMessages: []*secv1.Scan{runningScan(), finishedScan()}}
	c := startFake(t, svc)

	got, err := c.WaitForScan(context.Background(), "acme", "scan-1")
	if err != nil {
		t.Fatalf("WaitForScan: %v", err)
	}
	if got.GetStatus() != secv1.Status_STATUS_SUCCESS {
		t.Fatalf("status = %v, want STATUS_SUCCESS", got.GetStatus())
	}
	svc.mu.Lock()
	defer svc.mu.Unlock()
	if svc.getCalls != 0 {
		t.Fatalf("WaitForScan polled %d times when the stream worked; it should not have polled at all", svc.getCalls)
	}
}

func TestWaitForScanFallsBackToPolling(t *testing.T) {
	// An older server answers Unimplemented for a streaming RPC it does not
	// have. The wrapper must still return a final scan.
	svc := &fakeService{
		watchErr: status.Error(codes.Unimplemented, "no WatchScan here"),
		scans:    []*secv1.Scan{runningScan(), finishedScan()},
	}
	c := startFake(t, svc, sdk.WithWatchFallbackInterval(time.Millisecond))

	got, err := c.WaitForScan(context.Background(), "acme", "scan-1")
	if err != nil {
		t.Fatalf("WaitForScan: %v", err)
	}
	if got.GetStatus() != secv1.Status_STATUS_SUCCESS {
		t.Fatalf("status = %v, want STATUS_SUCCESS", got.GetStatus())
	}
	svc.mu.Lock()
	defer svc.mu.Unlock()
	if svc.getCalls < 2 {
		t.Fatalf("GetScan called %d times, want at least 2 (one running, one finished)", svc.getCalls)
	}
}

func TestWaitForScanReturnsRealErrors(t *testing.T) {
	// NotFound is the server's answer, not a transport problem, so it must not
	// trigger the polling fallback.
	svc := &fakeService{watchErr: status.Error(codes.NotFound, "no such scan")}
	c := startFake(t, svc, sdk.WithWatchFallbackInterval(time.Millisecond))

	_, err := c.WaitForScan(context.Background(), "acme", "scan-1")
	if got := status.Code(err); got != codes.NotFound {
		t.Fatalf("want NotFound, got %v (%v)", got, err)
	}
	svc.mu.Lock()
	defer svc.mu.Unlock()
	if svc.getCalls != 0 {
		t.Fatalf("fell back to polling after a NotFound; GetScan called %d times", svc.getCalls)
	}
}

func TestWaitForScanHonoursContextCancellation(t *testing.T) {
	// The scan never finishes, so only the context can end this.
	svc := &fakeService{
		watchErr: status.Error(codes.Unimplemented, "no WatchScan here"),
		scans:    []*secv1.Scan{runningScan()},
	}
	c := startFake(t, svc, sdk.WithWatchFallbackInterval(time.Millisecond))

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := c.WaitForScan(ctx, "acme", "scan-1")
	if err == nil {
		t.Fatal("WaitForScan returned no error after its context expired")
	}
	if !errors.Is(err, context.DeadlineExceeded) && status.Code(err) != codes.DeadlineExceeded {
		t.Fatalf("want a deadline error, got %v", err)
	}
}

func TestRequestBuildersPutTheValueInTheRightField(t *testing.T) {
	// Each scanner reads exactly one input; a value in the wrong field is a
	// server-side validation error the builders exist to prevent.
	if got := sdk.TrivyScan("acme", "nginx:latest"); got.GetImage() != "nginx:latest" || got.GetTarget() != "" {
		t.Errorf("TrivyScan should set image only, got %+v", got)
	}
	if got := sdk.NucleiScan("acme", "https://example.com"); got.GetTarget() != "https://example.com" || got.GetImage() != "" {
		t.Errorf("NucleiScan should set target only, got %+v", got)
	}
	if got := sdk.SemgrepScan("acme", "repo"); got.GetPath() != "repo" || got.GetTarget() != "" {
		t.Errorf("SemgrepScan should set path only, got %+v", got)
	}
	if got := sdk.ZAPScan("acme", "https://example.com", "baseline"); got.GetMode() != "baseline" {
		t.Errorf("ZAPScan should carry the mode, got %+v", got)
	}
}

func TestWithMetadataRejectsUnrepresentableValues(t *testing.T) {
	// Failing here is the point: the server would otherwise drop the metadata
	// silently, and the caller would never learn it was lost.
	if _, err := sdk.WithMetadata(sdk.TrivyScan("acme", "nginx:latest"), map[string]any{
		"bad": make(chan int),
	}); err == nil {
		t.Fatal("WithMetadata accepted a value that cannot be sent on the wire")
	}
}

func TestInsecureIsTheDefaultDial(t *testing.T) {
	// Documented behaviour: New without a TLS option dials in plaintext.
	c, err := sdk.New("passthrough:///bufnet", sdk.WithDialOptions(
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	))
	if err != nil {
		t.Fatalf("sdk.New: %v", err)
	}
	defer c.Close()
	if c.Conn() == nil {
		t.Fatal("New returned a client with no connection")
	}
}
