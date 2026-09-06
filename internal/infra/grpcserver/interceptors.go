package grpcserver

import (
	"context"
	"crypto/subtle"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/bryanwahyu/automaton-sec/internal/middleware"
)

// AuthConfig holds the credentials the gRPC server enforces.
//
// There is no webhook-signature equivalent here. The HTTP signature covers the
// exact bytes of a request body; a gRPC caller never handles those bytes
// because the client library serializes the message, so there is nothing
// stable to sign. gRPC authenticates with API keys, and the signed webhook
// stays HTTP-only for CI systems that already sign their payloads.
type AuthConfig struct {
	// Disabled turns off authentication. Development only.
	Disabled bool
	// APIKeys are accepted as "authorization: Bearer <key>" metadata.
	APIKeys []string
}

// healthMethodPrefix identifies the standard health service.
//
// Health is served without a credential and without a rate-limit budget, the
// same way the HTTP router leaves /health and /ready open: a probe must not
// need a secret to run, and the response exposes no scan data. Everything else
// — reflection included, since it discloses the schema — takes an API key.
const healthMethodPrefix = "/grpc.health.v1.Health/"

func isPublicMethod(fullMethod string) bool {
	return strings.HasPrefix(fullMethod, healthMethodPrefix)
}

// tenantCarrier is satisfied by every request message, because every one of
// them has a `tenant` field. Reading it through this interface keeps tenant
// validation in one interceptor instead of the top of every handler.
type tenantCarrier interface{ GetTenant() string }

// authUnary rejects a call without a valid API key before it reaches a handler.
func (a AuthConfig) authUnary(ctx context.Context) error {
	if a.Disabled {
		return nil
	}
	if len(a.APIKeys) == 0 {
		return status.Error(codes.Unauthenticated, "no API keys are configured on this server")
	}
	presented := bearerToken(ctx)
	if presented == "" {
		return status.Error(codes.Unauthenticated, "missing authorization: Bearer <api-key> metadata")
	}
	for _, key := range a.APIKeys {
		if key != "" && subtle.ConstantTimeCompare([]byte(key), []byte(presented)) == 1 {
			return nil
		}
	}
	return status.Error(codes.Unauthenticated, "invalid API key")
}

// bearerToken reads the bearer credential out of request metadata. gRPC
// lowercases metadata keys, so only "authorization" needs checking.
func bearerToken(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	for _, v := range md.Get("authorization") {
		const prefix = "bearer "
		if len(v) > len(prefix) && strings.EqualFold(v[:len(prefix)], prefix) {
			return strings.TrimSpace(v[len(prefix):])
		}
	}
	return ""
}

// validateTenant applies the same rules the HTTP router applies to the tenant
// path segment. A request type without a tenant field passes through, which is
// what the health and reflection services need.
func validateTenant(req any) error {
	carrier, ok := req.(tenantCarrier)
	if !ok {
		return nil
	}
	if err := middleware.ValidateTenantID(carrier.GetTenant()); err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	return nil
}

// rateLimitKey mirrors the HTTP limiter's key: tenant plus caller address, so
// one noisy tenant cannot exhaust another's budget and one noisy address
// cannot exhaust a tenant's.
func rateLimitKey(ctx context.Context, req any) string {
	tenant := ""
	if carrier, ok := req.(tenantCarrier); ok {
		tenant = carrier.GetTenant()
	}
	addr := ""
	if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
		addr = p.Addr.String()
	}
	return tenant + ":" + addr
}

// UnaryInterceptor runs auth, tenant validation and rate limiting in that
// order, then hands off to the handler.
//
// The order matters: an unauthenticated caller must not be able to consume a
// tenant's rate-limit budget.
func (s *Server) UnaryInterceptor(
	ctx context.Context,
	req any,
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (any, error) {
	if isPublicMethod(info.FullMethod) {
		return handler(ctx, req)
	}
	if err := s.auth.authUnary(ctx); err != nil {
		return nil, err
	}
	if err := validateTenant(req); err != nil {
		return nil, err
	}
	if !s.limiter.Allow(rateLimitKey(ctx, req)) {
		return nil, status.Error(codes.ResourceExhausted, "rate limit exceeded, please try again later")
	}
	return handler(ctx, req)
}

// StreamInterceptor is the streaming half of UnaryInterceptor.
//
// The tenant and rate-limit checks need the request message, which for a
// server-streaming RPC only exists after the handler receives it. Wrapping the
// stream lets those checks run against the first message received rather than
// being skipped entirely on streams.
func (s *Server) StreamInterceptor(
	srv any,
	ss grpc.ServerStream,
	info *grpc.StreamServerInfo,
	handler grpc.StreamHandler,
) error {
	if isPublicMethod(info.FullMethod) {
		return handler(srv, ss)
	}
	if err := s.auth.authUnary(ss.Context()); err != nil {
		return err
	}
	return handler(srv, &guardedStream{ServerStream: ss, server: s})
}

// guardedStream applies the per-request checks to messages as they arrive.
type guardedStream struct {
	grpc.ServerStream
	server  *Server
	checked bool
}

func (g *guardedStream) RecvMsg(m any) error {
	if err := g.ServerStream.RecvMsg(m); err != nil {
		return err
	}
	if g.checked {
		return nil
	}
	g.checked = true
	if err := validateTenant(m); err != nil {
		return err
	}
	if !g.server.limiter.Allow(rateLimitKey(g.Context(), m)) {
		return status.Error(codes.ResourceExhausted, "rate limit exceeded, please try again later")
	}
	return nil
}
