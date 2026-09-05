package application

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestPoolRejectsWhenSaturated(t *testing.T) {
	pool := NewPool(1, time.Minute)

	release := make(chan struct{})
	started := make(chan struct{})
	if err := pool.Submit(func(context.Context) {
		close(started)
		<-release
	}); err != nil {
		t.Fatalf("first submit: %v", err)
	}
	<-started

	if err := pool.Submit(func(context.Context) {}); !errors.Is(err, ErrBusy) {
		t.Fatalf("second submit = %v, want ErrBusy", err)
	}

	close(release)
	if err := pool.Wait(context.Background()); err != nil {
		t.Fatalf("Wait: %v", err)
	}

	// The slot must be reusable once the first job drains.
	if err := pool.Submit(func(context.Context) {}); err != nil {
		t.Fatalf("submit after drain: %v", err)
	}
	if err := pool.Wait(context.Background()); err != nil {
		t.Fatalf("Wait: %v", err)
	}
}

func TestPoolAppliesTimeout(t *testing.T) {
	pool := NewPool(1, 20*time.Millisecond)

	var deadlineHit atomic.Bool
	if err := pool.Submit(func(ctx context.Context) {
		<-ctx.Done()
		deadlineHit.Store(errors.Is(ctx.Err(), context.DeadlineExceeded))
	}); err != nil {
		t.Fatalf("submit: %v", err)
	}

	if err := pool.Wait(context.Background()); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if !deadlineHit.Load() {
		t.Fatal("job context should have hit its deadline")
	}
}

func TestPoolJobOutlivesTheSubmittingContext(t *testing.T) {
	pool := NewPool(1, time.Minute)

	// A scan must not be cancelled just because the HTTP request that queued it
	// has already been answered.
	reqCtx, cancel := context.WithCancel(context.Background())
	var live atomic.Bool
	if err := pool.Submit(func(ctx context.Context) {
		cancel()
		time.Sleep(10 * time.Millisecond)
		live.Store(ctx.Err() == nil)
	}); err != nil {
		t.Fatalf("submit: %v", err)
	}
	<-reqCtx.Done()

	if err := pool.Wait(context.Background()); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if !live.Load() {
		t.Fatal("job context should be independent of the caller's context")
	}
}

func TestPoolWaitRespectsItsOwnDeadline(t *testing.T) {
	pool := NewPool(1, time.Minute)

	release := make(chan struct{})
	if err := pool.Submit(func(context.Context) { <-release }); err != nil {
		t.Fatalf("submit: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := pool.Wait(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Wait = %v, want DeadlineExceeded", err)
	}

	close(release)
	_ = pool.Wait(context.Background())
}

func TestNewPoolClampsInvalidSettings(t *testing.T) {
	pool := NewPool(0, 0)
	if pool.Capacity() != 1 {
		t.Fatalf("Capacity = %d, want 1", pool.Capacity())
	}
	if pool.timeout != 30*time.Minute {
		t.Fatalf("timeout = %s, want 30m", pool.timeout)
	}
}
