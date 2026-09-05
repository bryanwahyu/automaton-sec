package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bryanwahyu/automaton-sec/internal/application"
	appscans "github.com/bryanwahyu/automaton-sec/internal/application/scans"
	domain "github.com/bryanwahyu/automaton-sec/internal/domain/scans"
)

const testKey = "s3cret"

func newStubService() *appscans.Service {
	return &appscans.Service{
		Repo:      stubRepo{},
		Runner:    stubRunner{},
		Artifacts: stubStore{},
		Clock:     application.SystemClock{},
	}
}

func testRouter(t *testing.T, pool *application.Pool) http.Handler {
	t.Helper()
	if pool == nil {
		pool = application.NewPool(1, time.Minute)
	}
	return NewRouter(Deps{
		ScansSvc: newStubService(),
		Pool:     pool,
		// Loopback targets are allowed so these tests never touch DNS.
		Policy: domain.TargetPolicy{AllowPrivateTargets: true},
		Auth: AuthConfig{
			WebhookHMACKey: []byte(testKey),
			APIKeys:        []string{"api-key-1"},
		},
	})
}

func post(t *testing.T, h http.Handler, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestHealthNeedsNoCredential(t *testing.T) {
	rec := httptest.NewRecorder()
	testRouter(t, nil).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestWebhookRejectsMissingAndBadSignatures(t *testing.T) {
	h := testRouter(t, nil)
	body := `{"tool":"nuclei","target":"http://127.0.0.1/"}`

	if rec := post(t, h, "/v1/acme/webhook/security-scan", body, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned request: status = %d, want 401", rec.Code)
	}

	bad := map[string]string{"X-Signature": "deadbeef"}
	if rec := post(t, h, "/v1/acme/webhook/security-scan", body, bad); rec.Code != http.StatusUnauthorized {
		t.Fatalf("badly signed request: status = %d, want 401", rec.Code)
	}
}

func TestWebhookAcceptsAValidSignature(t *testing.T) {
	body := `{"tool":"nuclei","target":"http://127.0.0.1/"}`
	sig := map[string]string{"X-Signature": SignBody([]byte(testKey), []byte(body))}

	rec := post(t, testRouter(t, nil), "/v1/acme/webhook/security-scan", body, sig)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", rec.Code, rec.Body.String())
	}
}

func TestWebhookRejectsAnUnsafeTargetWith400(t *testing.T) {
	// A flag-shaped target would be read as an argument by the scanner. The
	// caller should be told, not left to discover it in a background log.
	body := `{"tool":"nuclei","target":"-oJ/tmp/pwn"}`
	sig := map[string]string{"X-Signature": SignBody([]byte(testKey), []byte(body))}

	rec := post(t, testRouter(t, nil), "/v1/acme/webhook/security-scan", body, sig)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
	}
}

func TestWebhookAnswers429WhenThePoolIsSaturated(t *testing.T) {
	pool := application.NewPool(1, time.Minute)
	release := make(chan struct{})
	defer close(release)
	if err := pool.Submit(func(context.Context) { <-release }); err != nil {
		t.Fatalf("filling the pool: %v", err)
	}

	body := `{"tool":"nuclei","target":"http://127.0.0.1/"}`
	sig := map[string]string{"X-Signature": SignBody([]byte(testKey), []byte(body))}

	rec := post(t, testRouter(t, pool), "/v1/acme/webhook/security-scan", body, sig)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("a 429 should carry Retry-After")
	}
}

func TestReadRoutesRequireABearerKey(t *testing.T) {
	h := testRouter(t, nil)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/acme/scans", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if rec.Header().Get("WWW-Authenticate") == "" {
		t.Error("a 401 should carry WWW-Authenticate")
	}

	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/acme/scans", nil)
	req.Header.Set("Authorization", "Bearer wrong-key")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong key: status = %d, want 401", rec.Code)
	}
}

func TestRetryIsNotReachableWithGET(t *testing.T) {
	// Retry launches a real scan, so it must not sit behind a method a
	// prefetcher or crawler will follow.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/acme/scans/scan-1/retry", nil)
	req.Header.Set("Authorization", "Bearer api-key-1")
	testRouter(t, nil).ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

func TestAuthDisabledOpensEveryRoute(t *testing.T) {
	h := NewRouter(Deps{
		ScansSvc: newStubService(),
		Pool:     application.NewPool(1, time.Minute),
		Policy:   domain.TargetPolicy{AllowPrivateTargets: true},
		Auth:     AuthConfig{Disabled: true},
	})

	rec := post(t, h, "/v1/acme/webhook/security-scan", `{"tool":"nuclei","target":"http://127.0.0.1/"}`, nil)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", rec.Code, rec.Body.String())
	}
}

func TestSignBodyIsStableAndBodySensitive(t *testing.T) {
	a := SignBody([]byte(testKey), []byte(`{"a":1}`))
	if a != SignBody([]byte(testKey), []byte(`{"a":1}`)) {
		t.Fatal("SignBody should be deterministic")
	}
	if a == SignBody([]byte(testKey), []byte(`{"a":2}`)) {
		t.Fatal("a different body must produce a different signature")
	}
	if a == SignBody([]byte("other"), []byte(`{"a":1}`)) {
		t.Fatal("a different key must produce a different signature")
	}
}

func TestSplitAndTrim(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"analysis", []string{"analysis"}},
		{" analysis , ai ", []string{"analysis", "ai"}},
		{",,", nil},
		{"a,,b", []string{"a", "b"}},
	}
	for _, tc := range cases {
		got := splitAndTrim(tc.in)
		if len(got) != len(tc.want) {
			t.Fatalf("splitAndTrim(%q) = %v, want %v", tc.in, got, tc.want)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Fatalf("splitAndTrim(%q) = %v, want %v", tc.in, got, tc.want)
			}
		}
	}
}
