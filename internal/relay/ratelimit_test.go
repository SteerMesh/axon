package relay

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"golang.org/x/time/rate"
)

// tightConfig builds a RateLimitConfig with the same (limit, burst) applied
// to both buckets. Using limit 0 makes the limiter never refill mid-test --
// exactly `burst` requests succeed, then every subsequent one from that IP
// is rejected -- which keeps these tests deterministic without needing to
// wait on real wall-clock refill timing.
func tightConfig(burst int) RateLimitConfig {
	return RateLimitConfig{
		ConnectLimit:       0,
		ConnectBurst:       burst,
		PushSubscribeLimit: 0,
		PushSubscribeBurst: burst,
	}
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func doRequest(rl *RateLimiter, method, path, remoteAddr string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	req.RemoteAddr = remoteAddr
	rec := httptest.NewRecorder()
	rl.ServeHTTP(rec, req)
	return rec
}

// TestRateLimitBurstThenRejects confirms a burst of requests from one IP is
// let through up to the configured burst, and the next one is rejected with
// 429 -- with a Retry-After header set, since ConnectLimit here is nonzero.
func TestRateLimitBurstThenRejects(t *testing.T) {
	rl := WithRateLimit(okHandler(), RateLimitConfig{
		ConnectLimit: rate.Limit(10.0 / 60.0),
		ConnectBurst: 3,
	})
	defer rl.Stop()

	for i := 0; i < 3; i++ {
		if rec := doRequest(rl, http.MethodGet, "/v1/connect", "203.0.113.5:4000"); rec.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200 (within burst)", i, rec.Code)
		}
	}

	rec := doRequest(rl, http.MethodGet, "/v1/connect", "203.0.113.5:4001")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status after burst = %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("expected Retry-After header on 429 response")
	}
}

// TestRateLimitPerIPIsolation confirms the limiter is keyed per source IP:
// exhausting one IP's burst does not affect a different IP, and the same
// IP stays limited across different source ports (sourceIP must strip the
// port).
func TestRateLimitPerIPIsolation(t *testing.T) {
	rl := WithRateLimit(okHandler(), tightConfig(1))
	defer rl.Stop()

	if rec := doRequest(rl, http.MethodGet, "/v1/connect", "198.51.100.10:1111"); rec.Code != http.StatusOK {
		t.Fatalf("first request from IP A: status = %d, want 200", rec.Code)
	}
	// Same IP, different port -> still limited (sourceIP ignores port).
	if rec := doRequest(rl, http.MethodGet, "/v1/connect", "198.51.100.10:2222"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second request from IP A (different port): status = %d, want 429", rec.Code)
	}
	// A different IP must be unaffected by IP A's exhausted burst.
	if rec := doRequest(rl, http.MethodGet, "/v1/connect", "198.51.100.20:3333"); rec.Code != http.StatusOK {
		t.Fatalf("first request from IP B: status = %d, want 200 (IPs must be isolated)", rec.Code)
	}
}

// TestRateLimitExemptPathsNeverLimited confirms /healthz and GET
// /v1/vapid-key pass through regardless of request volume from one IP.
func TestRateLimitExemptPathsNeverLimited(t *testing.T) {
	rl := WithRateLimit(okHandler(), tightConfig(1))
	defer rl.Stop()

	for _, path := range []string{"/healthz", "/v1/vapid-key"} {
		for i := 0; i < 20; i++ {
			rec := doRequest(rl, http.MethodGet, path, "192.0.2.1:5555")
			if rec.Code != http.StatusOK {
				t.Fatalf("%s request %d: status = %d, want 200 (must never be rate limited)", path, i, rec.Code)
			}
		}
	}
}

// TestRateLimitOnlyAppliesToPushSubscribePostAndDelete confirms the push
// bucket only matches POST/DELETE on /v1/push/subscribe, per the design
// (GET is not part of that API and must not be throttled by this bucket).
func TestRateLimitOnlyAppliesToPushSubscribePostAndDelete(t *testing.T) {
	rl := WithRateLimit(okHandler(), tightConfig(1))
	defer rl.Stop()

	for i := 0; i < 5; i++ {
		if rec := doRequest(rl, http.MethodGet, "/v1/push/subscribe", "203.0.113.77:1"); rec.Code != http.StatusOK {
			t.Fatalf("GET /v1/push/subscribe request %d: status = %d, want 200", i, rec.Code)
		}
	}

	if rec := doRequest(rl, http.MethodPost, "/v1/push/subscribe", "203.0.113.77:1"); rec.Code != http.StatusOK {
		t.Fatalf("first POST: status = %d, want 200 (within burst)", rec.Code)
	}
	if rec := doRequest(rl, http.MethodDelete, "/v1/push/subscribe", "203.0.113.77:1"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second POST/DELETE: status = %d, want 429", rec.Code)
	}
}

// TestRateLimitIdleEvictionSweepRemovesStaleEntries confirms the sweep
// goroutine actually evicts an idle per-IP entry, using an injected short
// IdleTimeout/SweepInterval rather than waiting out a real 10-minute idle
// window. It inspects the bucket's entries map directly instead of
// re-probing via ServeHTTP, since calling allow() would itself refresh the
// entry's lastSeen and defeat the test.
func TestRateLimitIdleEvictionSweepRemovesStaleEntries(t *testing.T) {
	rl := WithRateLimit(okHandler(), RateLimitConfig{
		ConnectBurst:       1,
		PushSubscribeBurst: 1,
		IdleTimeout:        20 * time.Millisecond,
		SweepInterval:      5 * time.Millisecond,
	})
	defer rl.Stop()

	const ip = "203.0.113.9"
	if rec := doRequest(rl, http.MethodGet, "/v1/connect", ip+":9999"); rec.Code != http.StatusOK {
		t.Fatalf("seed request: status = %d, want 200", rec.Code)
	}

	connectBucket := rl.buckets[0]
	if connectBucket.label != "connect" {
		t.Fatalf("buckets[0].label = %q, want %q (test relies on bucket order)", connectBucket.label, "connect")
	}
	if _, ok := connectBucket.entries.Load(ip); !ok {
		t.Fatal("expected a limiter entry to exist for the IP right after the seed request")
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := connectBucket.entries.Load(ip); !ok {
			return // evicted by the sweep
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("stale entry was not evicted by the sweep within the deadline")
}

// TestRateLimitedTotalIncrementsWithPathLabel confirms
// axon_relay_rate_limited_total increments with the bounded "connect" /
// "push_subscribe" label values (never a raw URL path) on rejection, and
// only for the bucket that actually rejected.
func TestRateLimitedTotalIncrementsWithPathLabel(t *testing.T) {
	rl := WithRateLimit(okHandler(), tightConfig(1))
	defer rl.Stop()

	connectBefore := testutil.ToFloat64(rateLimitedTotal.WithLabelValues("connect"))
	pushBefore := testutil.ToFloat64(rateLimitedTotal.WithLabelValues("push_subscribe"))

	const ip = "203.0.113.42:1"
	doRequest(rl, http.MethodGet, "/v1/connect", ip) // consumes the burst
	doRequest(rl, http.MethodGet, "/v1/connect", ip) // rejected

	if got := testutil.ToFloat64(rateLimitedTotal.WithLabelValues("connect")); got != connectBefore+1 {
		t.Fatalf("connect rate-limited counter = %v, want %v", got, connectBefore+1)
	}
	if got := testutil.ToFloat64(rateLimitedTotal.WithLabelValues("push_subscribe")); got != pushBefore {
		t.Fatalf("push_subscribe rate-limited counter = %v, want unchanged %v", got, pushBefore)
	}
}

// TestDefaultRateLimitConfigMatchesProvisionalDefaults pins
// DefaultRateLimitConfig to the exact suggested starting points from the
// design: burst 5 / sustained 10 per minute on /v1/connect, burst 10 /
// sustained 20 per minute on /v1/push/subscribe.
func TestDefaultRateLimitConfigMatchesProvisionalDefaults(t *testing.T) {
	cfg := DefaultRateLimitConfig()
	if cfg.ConnectBurst != 5 {
		t.Errorf("ConnectBurst = %d, want 5", cfg.ConnectBurst)
	}
	if got, want := float64(cfg.ConnectLimit), 10.0/60.0; got != want {
		t.Errorf("ConnectLimit = %v, want %v", got, want)
	}
	if cfg.PushSubscribeBurst != 10 {
		t.Errorf("PushSubscribeBurst = %d, want 10", cfg.PushSubscribeBurst)
	}
	if got, want := float64(cfg.PushSubscribeLimit), 20.0/60.0; got != want {
		t.Errorf("PushSubscribeLimit = %v, want %v", got, want)
	}
}

// TestSourceIPFallsBackToRawRemoteAddr confirms sourceIP degrades
// gracefully (rather than panicking or erroring out the request) when
// RemoteAddr isn't in the usual "host:port" form.
func TestSourceIPFallsBackToRawRemoteAddr(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/connect", nil)
	req.RemoteAddr = "not-a-host-port"
	if got := sourceIP(req); got != "not-a-host-port" {
		t.Fatalf("sourceIP(%q) = %q, want unchanged input as fallback", req.RemoteAddr, got)
	}
}

// TestRateLimitIntegrationWithRealHub wraps a real Hub with WithRateLimit
// at tight limits and hits /v1/connect repeatedly, over real HTTP, from one
// simulated source (a single client against httptest.NewServer, so every
// request shares the same loopback source IP). It confirms 429s start
// appearing once the burst is exceeded, without asserting anything about
// Hub's own (unrelated) auth/routing responses for the in-burst requests.
func TestRateLimitIntegrationWithRealHub(t *testing.T) {
	mate := newTestMate(t, "mate-ratelimit")
	hub := NewHub(mate.keys())
	rl := WithRateLimit(hub, tightConfig(2))
	defer rl.Stop()
	server := httptest.NewServer(rl)
	defer server.Close()

	url := server.URL + "/v1/connect?mate_id=mate-ratelimit&role=mate"

	sawTooManyRequests := false
	for i := 0; i < 5; i++ {
		resp, err := http.Get(url)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if i < 2 {
			if resp.StatusCode == http.StatusTooManyRequests {
				t.Fatalf("request %d (within burst) got 429", i)
			}
			continue
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			sawTooManyRequests = true
		}
	}
	if !sawTooManyRequests {
		t.Fatal("expected a 429 after exceeding the burst, got none")
	}
}
