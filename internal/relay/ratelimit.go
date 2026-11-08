package relay

import (
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Rate limiting here protects against connection-flood / resource-exhaustion
// from a source, not against credential guessing: Ed25519 verification
// (see security.VerifyRelayToken) is already computationally infeasible to
// brute-force, and the relay is self-hosted per-operator rather than a
// shared multi-tenant service (see AXON_RELAY_MATE_KEYS in
// cmd/axon-relay/main.go -- a hand-provisioned flat allowlist, no
// accounts/tenancy). So limiting is keyed on source IP (r.RemoteAddr), not
// on mate_id: mate_id is a low-entropy routing label, not a secret, and
// limiting by it would protect nothing extra. r.RemoteAddr is used rather
// than X-Forwarded-For because this topology makes no reverse-proxy trust
// assumption -- an attacker controls whatever header they send, so trusting
// X-Forwarded-For here would let them spoof their way around the limit
// entirely.
//
// This file is deliberately a cross-cutting HTTP middleware layered in front
// of Hub (see WithRateLimit), not logic inside hub.go's routing/auth path --
// rate limiting is an infra concern, not a routing/auth one, and keeping it
// here means it never needs to look at anything beyond request metadata
// (method, path, remote address), preserving the relay's content-blind
// invariant by construction.

// RateLimitConfig configures the two limiter buckets WithRateLimit applies.
// All four fields are provisional starting points (see cmd/axon-relay/main.go
// env vars) meant to be tuned once axon_relay_rate_limited_total shows real
// traffic patterns -- nothing here is load-bearing by value, only by shape.
type RateLimitConfig struct {
	// ConnectLimit/ConnectBurst bound /v1/connect, the WebSocket upgrade
	// endpoint. It gets the stricter bucket because the handshake (TCP +
	// TLS + WS) is expensive and runs before any auth check.
	ConnectLimit rate.Limit
	ConnectBurst int

	// PushSubscribeLimit/PushSubscribeBurst bound POST/DELETE
	// /v1/push/subscribe. Looser than /v1/connect: a plain HTTP
	// request/response is far cheaper than a WebSocket upgrade.
	PushSubscribeLimit rate.Limit
	PushSubscribeBurst int

	// IdleTimeout is how long a per-IP limiter entry may sit unused before
	// the sweep goroutine evicts it. Defaults to 10 minutes when zero.
	IdleTimeout time.Duration

	// SweepInterval is how often the eviction sweep runs. Defaults to
	// IdleTimeout/2 (so an idle entry is caught within roughly 1.5x
	// IdleTimeout) when zero. Exposed mainly so tests can inject a short
	// interval instead of waiting out a real 10-minute idle window.
	SweepInterval time.Duration
}

// DefaultRateLimitConfig returns the suggested provisional defaults: burst 5
// / sustained 10 per minute per IP on /v1/connect, burst 10 / sustained 20
// per minute per IP on /v1/push/subscribe.
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		ConnectLimit:       rate.Limit(10.0 / 60.0),
		ConnectBurst:       5,
		PushSubscribeLimit: rate.Limit(20.0 / 60.0),
		PushSubscribeBurst: 10,
	}
}

// limiterBucket is one rate-limited route: the path label used on
// axon_relay_rate_limited_total, the predicate selecting which requests it
// applies to, and its own per-IP limiter set.
type limiterBucket struct {
	label   string
	matches func(*http.Request) bool
	limit   rate.Limit
	burst   int
	entries sync.Map // remote IP (string) -> *limiterEntry
}

type limiterEntry struct {
	limiter    *rate.Limiter
	lastSeenMu sync.Mutex
	lastSeen   time.Time
}

func (b *limiterBucket) allow(ip string) bool {
	entry, _ := b.entries.LoadOrStore(ip, &limiterEntry{limiter: rate.NewLimiter(b.limit, b.burst)})
	e := entry.(*limiterEntry)
	e.lastSeenMu.Lock()
	e.lastSeen = time.Now()
	e.lastSeenMu.Unlock()
	return e.limiter.Allow()
}

// sweep evicts entries idle for longer than idleTimeout, bounding memory
// growth from a large number of distinct source IPs seen over time.
func (b *limiterBucket) sweep(idleTimeout time.Time) {
	b.entries.Range(func(key, value any) bool {
		e := value.(*limiterEntry)
		e.lastSeenMu.Lock()
		stale := e.lastSeen.Before(idleTimeout)
		e.lastSeenMu.Unlock()
		if stale {
			b.entries.Delete(key)
		}
		return true
	})
}

// RateLimiter is the http.Handler middleware built by WithRateLimit.
type RateLimiter struct {
	next    http.Handler
	buckets []*limiterBucket
	stop    chan struct{}
}

// WithRateLimit wraps next (the relay's Hub) with per-source-IP rate
// limiting on /v1/connect and POST/DELETE /v1/push/subscribe. /healthz and
// GET /v1/vapid-key are never rate-limited -- both are cheap and legitimate
// to poll -- and every other path passes through untouched (hub.go's own
// routing already 404s anything it doesn't recognize).
//
// The returned handler owns a background sweep goroutine; callers that need
// to stop it (tests, graceful shutdown) can do so via the Stop method,
// though for a long-running relay process letting it run for the process
// lifetime is the expected use.
func WithRateLimit(next http.Handler, cfg RateLimitConfig) *RateLimiter {
	idleTimeout := cfg.IdleTimeout
	if idleTimeout <= 0 {
		idleTimeout = 10 * time.Minute
	}
	sweepInterval := cfg.SweepInterval
	if sweepInterval <= 0 {
		sweepInterval = idleTimeout / 2
	}
	rl := &RateLimiter{
		next: next,
		buckets: []*limiterBucket{
			{
				label: "connect",
				matches: func(r *http.Request) bool {
					return r.URL.Path == "/v1/connect"
				},
				limit: cfg.ConnectLimit,
				burst: cfg.ConnectBurst,
			},
			{
				label: "push_subscribe",
				matches: func(r *http.Request) bool {
					return r.URL.Path == "/v1/push/subscribe" && (r.Method == http.MethodPost || r.Method == http.MethodDelete)
				},
				limit: cfg.PushSubscribeLimit,
				burst: cfg.PushSubscribeBurst,
			},
		},
		stop: make(chan struct{}),
	}
	go rl.sweepLoop(sweepInterval, idleTimeout)
	return rl
}

func (rl *RateLimiter) sweepLoop(interval, idleTimeout time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-rl.stop:
			return
		case <-ticker.C:
			cutoff := time.Now().Add(-idleTimeout)
			for _, bucket := range rl.buckets {
				bucket.sweep(cutoff)
			}
		}
	}
}

// Stop halts the background sweep goroutine. Safe to call at most once.
func (rl *RateLimiter) Stop() {
	close(rl.stop)
}

func (rl *RateLimiter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	for _, bucket := range rl.buckets {
		if !bucket.matches(r) {
			continue
		}
		ip := sourceIP(r)
		if !bucket.allow(ip) {
			rateLimitedTotal.WithLabelValues(bucket.label).Inc()
			if retryAfter := retryAfterSeconds(bucket.limit); retryAfter > 0 {
				w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
			}
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		break
	}
	rl.next.ServeHTTP(w, r)
}

// retryAfterSeconds derives a Retry-After value from a bucket's sustained
// rate: the time until one more token accrues. Returns 0 (meaning: omit the
// header) for a non-positive or infinite limit, which rate.Limiter permits
// but which has no meaningful "wait this long" interpretation.
func retryAfterSeconds(limit rate.Limit) int {
	if limit <= 0 || limit == rate.Inf {
		return 0
	}
	seconds := int(1/float64(limit)) + 1
	if seconds < 1 {
		seconds = 1
	}
	return seconds
}

// sourceIP extracts the connecting source IP from r.RemoteAddr, which
// net/http sets to "ip:port" for every request regardless of transport.
// Deliberately not X-Forwarded-For or any other client-supplied header --
// see the package-level comment on why this topology trusts only
// RemoteAddr.
func sourceIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
