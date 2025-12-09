package middleware

import (
	"net/http"
	"sync"
	"time"
)

// TokenBucket implements token bucket rate limiting
type TokenBucket struct {
	mu           sync.Mutex
	capacity     int
	tokens       int
	refillRate   int           // tokens per second
	lastRefill   time.Time
}

func NewTokenBucket(capacity, refillRate int) *TokenBucket {
	return &TokenBucket{
		capacity:   capacity,
		tokens:     capacity,
		refillRate: refillRate,
		lastRefill: time.Now(),
	}
}

func (tb *TokenBucket) Allow() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	// Refill tokens based on time passed
	now := time.Now()
	elapsed := now.Sub(tb.lastRefill).Seconds()
	tokensToAdd := int(elapsed * float64(tb.refillRate))

	if tokensToAdd > 0 {
		tb.tokens += tokensToAdd
		if tb.tokens > tb.capacity {
			tb.tokens = tb.capacity
		}
		tb.lastRefill = now
	}

	// Check if we have tokens available
	if tb.tokens > 0 {
		tb.tokens--
		return true
	}

	return false
}

// RateLimiter manages rate limits per tenant
type RateLimiter struct {
	mu      sync.RWMutex
	buckets map[string]*TokenBucket
	capacity int
	refillRate int
}

func NewRateLimiter(capacity, refillRate int) *RateLimiter {
	rl := &RateLimiter{
		buckets: make(map[string]*TokenBucket),
		capacity: capacity,
		refillRate: refillRate,
	}

	// Start cleanup goroutine to remove old buckets
	go rl.cleanup()

	return rl
}

func (rl *RateLimiter) getBucket(key string) *TokenBucket {
	rl.mu.RLock()
	bucket, exists := rl.buckets[key]
	rl.mu.RUnlock()

	if exists {
		return bucket
	}

	// Create new bucket
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Double-check after acquiring write lock
	if bucket, exists := rl.buckets[key]; exists {
		return bucket
	}

	bucket = NewTokenBucket(rl.capacity, rl.refillRate)
	rl.buckets[key] = bucket
	return bucket
}

func (rl *RateLimiter) Allow(key string) bool {
	bucket := rl.getBucket(key)
	return bucket.Allow()
}

func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for key, bucket := range rl.buckets {
			bucket.mu.Lock()
			// Remove buckets that haven't been used in 10 minutes
			if now.Sub(bucket.lastRefill) > 10*time.Minute {
				delete(rl.buckets, key)
			}
			bucket.mu.Unlock()
		}
		rl.mu.Unlock()
	}
}

// RateLimitMiddleware creates a rate limiting middleware
// capacity: max tokens in bucket
// refillRate: tokens added per second
func RateLimitMiddleware(capacity, refillRate int) func(http.Handler) http.Handler {
	limiter := NewRateLimiter(capacity, refillRate)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip rate limit for health check
			if r.URL.Path == "/health" {
				next.ServeHTTP(w, r)
				return
			}

			// Use tenant + IP as rate limit key
			tenant := GetTenantFromContext(r.Context())
			ip := r.RemoteAddr
			key := tenant + ":" + ip

			if !limiter.Allow(key) {
				w.Header().Set("Retry-After", "60")
				http.Error(w, "rate limit exceeded, please try again later", http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
