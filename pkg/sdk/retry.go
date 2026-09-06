package sdk

import (
	"context"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// retryable reports whether another attempt could plausibly succeed.
//
// Unavailable and DeadlineExceeded are transport hiccups. ResourceExhausted is
// the server saying the scanner pool is full or the rate limit is hit, which
// clears on its own. Everything else — a bad argument, a missing scan, a
// rejected key — will fail identically no matter how often it is sent.
func retryable(err error) bool {
	switch status.Code(err) {
	case codes.Unavailable, codes.DeadlineExceeded, codes.ResourceExhausted:
		return true
	default:
		return false
	}
}

// do runs call with the configured retry policy.
//
// The caller's context still bounds everything: a cancelled context stops the
// loop immediately rather than sleeping out the backoff.
func do[T any](ctx context.Context, c *Client, call func(context.Context) (T, error)) (T, error) {
	var (
		zero    T
		lastErr error
	)

	attempts := c.retry.MaxAttempts
	if attempts < 1 {
		attempts = 1
	}
	delay := c.retry.BaseDelay
	if delay <= 0 {
		delay = DefaultRetryPolicy.BaseDelay
	}
	maxDelay := c.retry.MaxDelay
	if maxDelay <= 0 {
		maxDelay = DefaultRetryPolicy.MaxDelay
	}

	for attempt := 1; ; attempt++ {
		callCtx, cancel := c.callContext(ctx)
		out, err := call(callCtx)
		cancel()
		if err == nil {
			return out, nil
		}
		lastErr = err

		// A caller who gave up outranks the retry policy; without this check a
		// cancelled context still burns through every remaining attempt.
		if ctx.Err() != nil {
			return zero, ctx.Err()
		}
		if attempt >= attempts || !retryable(err) {
			return zero, lastErr
		}

		select {
		case <-ctx.Done():
			return zero, ctx.Err()
		case <-time.After(delay):
		}
		if delay *= 2; delay > maxDelay {
			delay = maxDelay
		}
	}
}
