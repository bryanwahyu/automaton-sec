package application

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ErrBusy is returned when every worker slot is occupied.
var ErrBusy = errors.New("scanner pool is saturated")

// Pool bounds how many scans run at once, gives each one a deadline, and keeps
// track of them so shutdown can wait instead of killing work mid-run.
//
// Scanners are heavy processes (ZAP and trivy in particular), so an unbounded
// goroutine per webhook call is an OOM waiting to happen.
type Pool struct {
	sem     chan struct{}
	wg      sync.WaitGroup
	timeout time.Duration
}

// NewPool builds a pool allowing max concurrent jobs, each bounded by timeout.
func NewPool(max int, timeout time.Duration) *Pool {
	if max <= 0 {
		max = 1
	}
	if timeout <= 0 {
		timeout = 30 * time.Minute
	}
	return &Pool{sem: make(chan struct{}, max), timeout: timeout}
}

// Submit runs fn in the background with a deadline. It returns ErrBusy
// immediately rather than queueing when the pool is full, so the caller can
// answer 429 instead of letting requests pile up invisibly.
//
// The context handed to fn is detached from the request: the work must outlive
// the HTTP response that started it.
func (p *Pool) Submit(fn func(ctx context.Context)) error {
	select {
	case p.sem <- struct{}{}:
	default:
		return ErrBusy
	}

	p.wg.Add(1)
	go func() {
		defer func() {
			<-p.sem
			p.wg.Done()
		}()

		ctx, cancel := context.WithTimeout(context.Background(), p.timeout)
		defer cancel()
		fn(ctx)
	}()
	return nil
}

// Wait blocks until every submitted job has finished or ctx is done.
func (p *Pool) Wait(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// InFlight reports how many jobs are currently running.
func (p *Pool) InFlight() int { return len(p.sem) }

// Capacity reports the configured maximum number of concurrent jobs.
func (p *Pool) Capacity() int { return cap(p.sem) }
