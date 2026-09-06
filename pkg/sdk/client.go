// Package sdk is a typed client for the automaton-sec gRPC API.
//
// The generated stubs in gen/go are usable on their own. This wrapper exists
// for the things every caller would otherwise write again: attaching the API
// key to each call, a default deadline, retry with backoff on the failures that
// are worth retrying, and WaitForScan — which replaces the polling loop clients
// used to reimplement against the REST API.
//
//	c, err := sdk.New("api.example.com:9000",
//	    sdk.WithAPIKey(os.Getenv("AUTOMATON_SEC_API_KEY")),
//	    sdk.WithTLS(),
//	)
//	if err != nil { ... }
//	defer c.Close()
//
//	res, err := c.TriggerScan(ctx, sdk.TrivyScan("acme", "nginx:latest"))
//	scan, err := c.WaitForScan(ctx, "acme", res.GetScanId())
package sdk

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	secv1 "github.com/bryanwahyu/automaton-sec/gen/go/automaton/sec/v1"
)

// Client talks to one automaton-sec server.
//
// It is safe for concurrent use: the underlying gRPC connection multiplexes
// calls, so one Client per process is the intended shape.
type Client struct {
	conn     *grpc.ClientConn
	scans    secv1.ScanServiceClient
	analyses secv1.AnalysisServiceClient

	apiKey  string
	timeout time.Duration
	retry   RetryPolicy
	watch   time.Duration
}

// Option configures a Client. Options are applied in order.
type Option func(*options)

type options struct {
	apiKey      string
	timeout     time.Duration
	retry       RetryPolicy
	dialOptions []grpc.DialOption
	creds       credentials.TransportCredentials
	watch       time.Duration
}

// RetryPolicy bounds how hard the client tries before giving up.
type RetryPolicy struct {
	// MaxAttempts includes the first try. One or less disables retrying.
	MaxAttempts int
	// BaseDelay is the wait after the first failure; it doubles each attempt.
	BaseDelay time.Duration
	// MaxDelay caps the doubling.
	MaxDelay time.Duration
}

// DefaultRetryPolicy retries a handful of times over a few seconds. It applies
// only to failures that are worth retrying — see retryable.
var DefaultRetryPolicy = RetryPolicy{
	MaxAttempts: 4,
	BaseDelay:   200 * time.Millisecond,
	MaxDelay:    2 * time.Second,
}

// defaultTimeout bounds a single unary call. Streams are not bounded by it:
// WatchScan can legitimately run for the length of a scan.
const defaultTimeout = 30 * time.Second

// defaultWatchFallbackInterval is how often WaitForScan re-reads a scan when
// the stream is unavailable — an old server, or a proxy that will not carry a
// long-lived stream.
const defaultWatchFallbackInterval = 3 * time.Second

// WithAPIKey sends key as "authorization: Bearer <key>" on every call. The
// server accepts nothing else; a signed webhook stays HTTP-only because a gRPC
// caller never handles the request bytes it would have to sign.
func WithAPIKey(key string) Option {
	return func(o *options) { o.apiKey = key }
}

// WithTLS dials with TLS using the host's root certificate pool.
func WithTLS() Option {
	return func(o *options) {
		o.creds = credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})
	}
}

// WithTLSConfig dials with TLS using cfg — for a private CA or a pinned
// certificate.
func WithTLSConfig(cfg *tls.Config) Option {
	return func(o *options) { o.creds = credentials.NewTLS(cfg) }
}

// WithInsecure dials without TLS. It is the default, because the common
// deployment puts the server behind a mesh or a local network; say it
// explicitly when you mean it.
func WithInsecure() Option {
	return func(o *options) { o.creds = insecure.NewCredentials() }
}

// WithTimeout bounds each unary call. Zero restores the default; a negative
// value disables the client-side deadline entirely, leaving only the caller's
// own context.
func WithTimeout(d time.Duration) Option {
	return func(o *options) { o.timeout = d }
}

// WithRetryPolicy replaces the default retry policy.
func WithRetryPolicy(p RetryPolicy) Option {
	return func(o *options) { o.retry = p }
}

// WithWatchFallbackInterval sets how often WaitForScan polls when it cannot
// use the stream.
func WithWatchFallbackInterval(d time.Duration) Option {
	return func(o *options) { o.watch = d }
}

// WithDialOptions passes gRPC dial options through untouched, for anything
// this wrapper does not model.
func WithDialOptions(opts ...grpc.DialOption) Option {
	return func(o *options) { o.dialOptions = append(o.dialOptions, opts...) }
}

// New dials target, e.g. "api.example.com:9000".
//
// The connection is lazy: New returning nil does not mean the server is
// reachable, only that the target parsed. The first call reports a connection
// failure.
func New(target string, opts ...Option) (*Client, error) {
	o := options{
		timeout: defaultTimeout,
		retry:   DefaultRetryPolicy,
		watch:   defaultWatchFallbackInterval,
	}
	for _, opt := range opts {
		opt(&o)
	}
	if o.creds == nil {
		o.creds = insecure.NewCredentials()
	}
	if o.watch <= 0 {
		o.watch = defaultWatchFallbackInterval
	}

	dialOpts := append([]grpc.DialOption{grpc.WithTransportCredentials(o.creds)}, o.dialOptions...)
	conn, err := grpc.NewClient(target, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", target, err)
	}

	return &Client{
		conn:     conn,
		scans:    secv1.NewScanServiceClient(conn),
		analyses: secv1.NewAnalysisServiceClient(conn),
		apiKey:   o.apiKey,
		timeout:  o.timeout,
		retry:    o.retry,
		watch:    o.watch,
	}, nil
}

// Close releases the connection.
func (c *Client) Close() error { return c.conn.Close() }

// Conn exposes the underlying connection, for callers that want the generated
// stubs directly.
func (c *Client) Conn() *grpc.ClientConn { return c.conn }

// authContext attaches the API key. It does not set a deadline, so it is what
// streams use.
func (c *Client) authContext(ctx context.Context) context.Context {
	if c.apiKey == "" {
		return ctx
	}
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+c.apiKey)
}

// callContext attaches the API key and the per-call deadline. The caller's own
// deadline wins when it is tighter, because context.WithTimeout never extends
// an existing one.
func (c *Client) callContext(ctx context.Context) (context.Context, context.CancelFunc) {
	ctx = c.authContext(ctx)
	if c.timeout <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, c.timeout)
}
