package ai

import "errors"

// ErrQuotaExceeded indicates the AI provider returned a quota/limit error (HTTP 429 or similar).
var ErrQuotaExceeded = errors.New("ai quota exceeded")

