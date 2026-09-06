// Package grpcserver serves the same use cases as the HTTP router over gRPC.
//
// Nothing in here reimplements application logic. The services call the same
// application.Service values the HTTP handlers call, errors are classified by
// the shared apierr package, and the cross-cutting concerns the HTTP router
// puts in middleware are interceptors over the same primitives.
package grpcserver

import (
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"

	secv1 "github.com/bryanwahyu/automaton-sec/gen/go/automaton/sec/v1"
	"github.com/bryanwahyu/automaton-sec/internal/apierr"
	"github.com/bryanwahyu/automaton-sec/internal/application"
	appai "github.com/bryanwahyu/automaton-sec/internal/application/ai"
	appscans "github.com/bryanwahyu/automaton-sec/internal/application/scans"
	serrdom "github.com/bryanwahyu/automaton-sec/internal/domain/scanerrors"
	domain "github.com/bryanwahyu/automaton-sec/internal/domain/scans"
	"github.com/bryanwahyu/automaton-sec/internal/middleware"
)

// Deps is everything the gRPC server needs. It mirrors httpserver.Deps because
// both surfaces sit on the same application services.
type Deps struct {
	ScansSvc *appscans.Service
	AISvc    *appai.Service
	ScanErrs serrdom.Repository
	// Pool bounds background scan execution. It is the same pool the HTTP
	// webhook submits to, so the two surfaces share one capacity budget.
	Pool *application.Pool
	// Policy rejects unsafe scan targets before a scan is queued.
	Policy domain.TargetPolicy
	Auth   AuthConfig
	// RateLimitBurst and RateLimitPerMinute bound requests per tenant+peer.
	RateLimitBurst     int
	RateLimitPerMinute int
	// WatchInterval is how often WatchScan re-reads a running scan. Zero uses
	// defaultWatchInterval.
	WatchInterval time.Duration
}

// Server holds the state the interceptors and services share.
type Server struct {
	scansSvc      *appscans.Service
	aiSvc         *appai.Service
	serrRepo      serrdom.Repository
	pool          *application.Pool
	policy        domain.TargetPolicy
	auth          AuthConfig
	limiter       *middleware.RateLimiter
	watchInterval time.Duration
}

// New builds a *grpc.Server with both services, the standard health service
// and reflection registered.
//
// Health uses grpc.health.v1 rather than a bespoke RPC so off-the-shelf probes
// work; reflection is registered so grpcurl can talk to a running instance
// without a copy of the proto.
func New(deps Deps) *grpc.Server {
	burst := deps.RateLimitBurst
	if burst < 1 {
		burst = 20
	}
	// Tokens refill per second while the config expresses a sustained rate per
	// minute, exactly as the HTTP router does. Both are clamped: a zero burst
	// builds a bucket that can never hand out a token.
	refillPerSecond := deps.RateLimitPerMinute / 60
	if refillPerSecond < 1 {
		refillPerSecond = 1
	}

	watch := deps.WatchInterval
	if watch <= 0 {
		watch = defaultWatchInterval
	}

	s := &Server{
		scansSvc:      deps.ScansSvc,
		aiSvc:         deps.AISvc,
		serrRepo:      deps.ScanErrs,
		pool:          deps.Pool,
		policy:        deps.Policy,
		auth:          deps.Auth,
		limiter:       middleware.NewRateLimiter(burst, refillPerSecond),
		watchInterval: watch,
	}

	srv := grpc.NewServer(
		grpc.UnaryInterceptor(s.UnaryInterceptor),
		grpc.StreamInterceptor(s.StreamInterceptor),
	)

	secv1.RegisterScanServiceServer(srv, &scanService{Server: s})
	secv1.RegisterAnalysisServiceServer(srv, &analysisService{Server: s})

	hs := health.NewServer()
	hs.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	hs.SetServingStatus(secv1.ScanService_ServiceDesc.ServiceName, healthpb.HealthCheckResponse_SERVING)
	hs.SetServingStatus(secv1.AnalysisService_ServiceDesc.ServiceName, healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(srv, hs)

	reflection.Register(srv)
	return srv
}

// toStatus renders an internal error as a gRPC status using the same
// classification the HTTP router uses for its status codes.
func toStatus(err error) error {
	if err == nil {
		return nil
	}
	// An error a handler already expressed as a status — an interceptor
	// rejection, say — passes through unchanged.
	if _, ok := status.FromError(err); ok && status.Code(err) != codes.Unknown {
		return err
	}
	switch apierr.Classify(err) {
	case apierr.KindNotFound:
		return status.Error(codes.NotFound, "not found")
	case apierr.KindQuotaExceeded:
		return status.Error(codes.ResourceExhausted, "ai quota exceeded")
	case apierr.KindBusy:
		return status.Error(codes.ResourceExhausted, "scanner capacity reached, retry later")
	case apierr.KindInvalidArgument:
		return status.Error(codes.InvalidArgument, err.Error())
	default:
		return status.Error(codes.Internal, err.Error())
	}
}

// clampPageSize applies the same bounds the HTTP layer applies to list sizes.
func clampPageSize(n int32) int {
	if n <= 0 {
		return 20
	}
	if n > 100 {
		return 100
	}
	return int(n)
}

func clampPage(n int32) int {
	if n < 1 {
		return 1
	}
	return int(n)
}

func clampDays(n int32) int {
	if n <= 0 {
		return 7
	}
	if n > 365 {
		return 365
	}
	return int(n)
}
