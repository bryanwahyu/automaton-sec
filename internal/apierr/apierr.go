// Package apierr classifies an internal error once, so every transport reports
// the same failure the same way.
//
// The mapping used to live inside the HTTP router's wrap(). With a second
// surface answering the same use cases, a copy of it would drift: the same
// missing row would be a 404 on one and an Internal on the other.
package apierr

import (
	"database/sql"
	"errors"

	"github.com/bryanwahyu/automaton-sec/internal/application"
	domai "github.com/bryanwahyu/automaton-sec/internal/domain/ai"
)

// ErrNotFound is the sentinel a handler returns when a lookup came back empty
// without the driver reporting it. Repositories that do report it use
// sql.ErrNoRows; both classify the same way, so a caller cannot tell which
// layer noticed the row was missing.
var ErrNotFound = sql.ErrNoRows

// Kind is a transport-independent error class. Each transport decides how to
// render it — an HTTP status, a gRPC code — but not what it means.
type Kind int

const (
	// KindInternal is the fallback: a failure the caller cannot act on.
	KindInternal Kind = iota
	// KindNotFound means the requested row does not exist.
	KindNotFound
	// KindInvalidArgument means the caller sent something unusable.
	KindInvalidArgument
	// KindQuotaExceeded means the AI provider refused on quota grounds. It is
	// distinct from KindBusy because the caller can do nothing but wait for a
	// quota window, whereas capacity frees up on its own.
	KindQuotaExceeded
	// KindBusy means the scanner pool is saturated. Retrying later works.
	KindBusy
)

// invalidArgument marks an error as the caller's fault, so a transport answers
// 400 / InvalidArgument instead of 500 / Internal.
type invalidArgument struct{ error }

func (i invalidArgument) Unwrap() error { return i.error }

// InvalidArgument wraps err as a caller error. A nil err is returned unchanged
// so it can be used inline on a function that may not have failed.
func InvalidArgument(err error) error {
	if err == nil {
		return nil
	}
	return invalidArgument{err}
}

// IsInvalidArgument reports whether err was marked with InvalidArgument.
func IsInvalidArgument(err error) bool {
	var i invalidArgument
	return errors.As(err, &i)
}

// Classify maps err to the class every transport agrees on.
func Classify(err error) Kind {
	switch {
	case err == nil:
		return KindInternal
	case errors.Is(err, sql.ErrNoRows):
		return KindNotFound
	case errors.Is(err, domai.ErrQuotaExceeded):
		return KindQuotaExceeded
	case errors.Is(err, application.ErrBusy):
		return KindBusy
	case IsInvalidArgument(err):
		return KindInvalidArgument
	default:
		return KindInternal
	}
}
