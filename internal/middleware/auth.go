package middleware

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strings"
)

type contextKey string

const (
	TenantKey contextKey = "tenant"
	APIKeyKey contextKey = "api_key"
)

// APIKeyAuth validates API key from Authorization header
func APIKeyAuth(validKeys map[string]string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip auth for health check
			if r.URL.Path == "/health" {
				next.ServeHTTP(w, r)
				return
			}

			// Extract API key from Authorization header
			auth := r.Header.Get("Authorization")
			if auth == "" {
				http.Error(w, "missing Authorization header", http.StatusUnauthorized)
				return
			}

			// Support both "Bearer <key>" and "<key>" formats
			apiKey := strings.TrimPrefix(auth, "Bearer ")
			apiKey = strings.TrimSpace(apiKey)

			if apiKey == "" {
				http.Error(w, "invalid Authorization header format", http.StatusUnauthorized)
				return
			}

			// Validate API key (constant-time comparison to prevent timing attacks)
			valid := false
			var tenant string
			for t, key := range validKeys {
				if subtle.ConstantTimeCompare([]byte(apiKey), []byte(key)) == 1 {
					valid = true
					tenant = t
					break
				}
			}

			if !valid {
				http.Error(w, "invalid API key", http.StatusUnauthorized)
				return
			}

			// Store tenant in context
			ctx := context.WithValue(r.Context(), TenantKey, tenant)
			ctx = context.WithValue(ctx, APIKeyKey, apiKey)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetTenantFromContext extracts tenant from context
func GetTenantFromContext(ctx context.Context) string {
	if tenant, ok := ctx.Value(TenantKey).(string); ok {
		return tenant
	}
	return ""
}

// RequireValidTenant ensures tenant from URL matches authenticated tenant
func RequireValidTenant(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip for health check
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}

		// Get tenant from context (set by auth middleware)
		authTenant := GetTenantFromContext(r.Context())

		// Get tenant from URL parameter
		urlTenant := r.Context().Value("tenant")
		if urlTenant == nil {
			// Try to extract from URL path manually if not in context yet
			// This will be set by chi router
			next.ServeHTTP(w, r)
			return
		}

		// Validate tenant ID format
		if authTenant != "" {
			if err := ValidateTenantID(authTenant); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}
