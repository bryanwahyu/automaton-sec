package httpserver

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// AuthConfig holds the credentials the router enforces.
type AuthConfig struct {
	// Disabled turns off all authentication. Development only.
	Disabled bool
	// WebhookHMACKey is the shared secret for webhook signatures. When empty,
	// webhook routes fall back to API-key authentication.
	WebhookHMACKey []byte
	// APIKeys are accepted as "Authorization: Bearer <key>".
	APIKeys []string
}

// maxWebhookBody bounds how much of a request body we will buffer in order to
// verify its signature.
const maxWebhookBody = 1 << 20 // 1 MiB

// requireAPIKey guards read routes with a bearer token.
func (a AuthConfig) requireAPIKey(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if a.Disabled {
			next.ServeHTTP(w, req)
			return
		}
		if len(a.APIKeys) == 0 {
			unauthorized(w, "no API keys are configured on this server")
			return
		}

		presented := bearerToken(req)
		if presented == "" {
			unauthorized(w, "missing Authorization: Bearer <api-key> header")
			return
		}
		for _, key := range a.APIKeys {
			if key != "" && subtle.ConstantTimeCompare([]byte(key), []byte(presented)) == 1 {
				next.ServeHTTP(w, req)
				return
			}
		}
		unauthorized(w, "invalid API key")
	})
}

// requireWebhookSignature guards the scan-trigger route.
//
// The body is read, verified against the X-Signature header, and then put back
// so the handler can decode it as usual.
func (a AuthConfig) requireWebhookSignature(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if a.Disabled {
			next.ServeHTTP(w, req)
			return
		}
		if len(a.WebhookHMACKey) == 0 {
			// No webhook secret configured: fall back to bearer auth so the
			// route is never left open.
			a.requireAPIKey(next).ServeHTTP(w, req)
			return
		}

		body, err := io.ReadAll(io.LimitReader(req.Body, maxWebhookBody))
		if err != nil {
			http.Error(w, "cannot read request body", http.StatusBadRequest)
			return
		}
		_ = req.Body.Close()
		req.Body = io.NopCloser(strings.NewReader(string(body)))

		presented := req.Header.Get("X-Signature")
		if presented == "" {
			unauthorized(w, "missing X-Signature header")
			return
		}
		presented = strings.TrimPrefix(presented, "sha256=")

		want := SignBody(a.WebhookHMACKey, body)
		if subtle.ConstantTimeCompare([]byte(want), []byte(strings.ToLower(presented))) != 1 {
			unauthorized(w, "invalid webhook signature")
			return
		}
		next.ServeHTTP(w, req)
	})
}

// SignBody returns the lowercase hex HMAC-SHA256 of body, the value a caller
// must send in X-Signature.
func SignBody(key, body []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

func bearerToken(req *http.Request) string {
	h := req.Header.Get("Authorization")
	if h == "" {
		return ""
	}
	const prefix = "bearer "
	if len(h) > len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
		return strings.TrimSpace(h[len(prefix):])
	}
	return ""
}

func unauthorized(w http.ResponseWriter, reason string) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="automaton-sec"`)
	http.Error(w, fmt.Sprintf("unauthorized: %s", reason), http.StatusUnauthorized)
}
