package relay

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics are registered exactly once, at package load, as package-level
// vars -- never inside NewHub or any other per-connection/per-Hub code
// path. internal/relay's own test suite constructs dozens of Hubs across
// hub_test.go and hub_push_test.go within a single test binary; if
// registration were tied to Hub construction (e.g. a prometheus.MustRegister
// call inside NewHub), the second Hub created in that binary would panic
// with "duplicate metrics collector registration attempted". Registering at
// var-init time sidesteps that entirely: Go runs package-level initializers
// once per process no matter how many Hub values get built afterward.
//
// These register against the default Prometheus registry (via promauto's
// package-level helpers, not promauto.With(customRegistry)) because
// cmd/axon-relay/main.go serves them with promhttp.Handler(), which reads
// from prometheus.DefaultGatherer.
var (
	// connectionsActive tracks live WebSocket peers by role ("mate" or
	// "device"). Incremented in Hub.register, decremented in
	// Hub.unregister -- the same two functions that already guard the
	// hub's mates/devices maps, so this stays exactly in sync with them.
	connectionsActive = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "axon_relay_connections_active",
		Help: "Number of currently connected relay WebSocket peers, by role.",
	}, []string{"role"})

	// authFailures counts rejected Relay Access Tokens by the reason
	// verifyRelayAccessToken's own branches distinguish. No token content,
	// claim values, or identities are ever included -- only the
	// classification of which check failed.
	authFailures = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "axon_relay_auth_failures_total",
		Help: "Relay Access Token verification failures, by reason.",
	}, []string{"reason"})

	// framesTotal counts routed frames by delivery outcome. Observed at
	// the three points readLoop already distinguishes an undeliverable
	// frame: immediate forward success, no connected peer with no push
	// fallback (device -> mate), and no connected peer with a Web Push
	// wake attempt (mate -> device).
	framesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "axon_relay_frames_total",
		Help: "Routed frames by delivery outcome.",
	}, []string{"result"})

	// frameBytes is a size-only histogram of routed frame bytes. It never
	// observes or exposes anything about a frame's content, only its wire
	// size, keeping it consistent with the relay's content-blind
	// invariant. Buckets run from 64B to MaxFrameBytes (128KiB), the
	// relay's hard per-frame ceiling (see MaxFrameBytes in hub.go).
	frameBytes = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "axon_relay_frame_bytes",
		Help:    "Size in bytes of routed frames (size only, never content).",
		Buckets: []float64{64, 256, 1024, 4096, 16384, 32768, 65536, MaxFrameBytes},
	})

	// pushTotal counts Web Push wake-notification attempts by outcome:
	// "sent" (delivered to the push service), "failed" (the send itself
	// errored), or "pruned" (the push service reported the subscription
	// dead via 404/410 and it was deleted).
	pushTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "axon_relay_push_total",
		Help: "Web Push wake notification attempts, by outcome.",
	}, []string{"result"})

	// rateLimitedTotal counts requests rejected by rate limiting, by path.
	// No rate limiting exists yet in this change -- this metric is defined
	// now so the follow-up rate-limiting task can increment it without
	// touching this file.
	rateLimitedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "axon_relay_rate_limited_total",
		Help: "Requests rejected by rate limiting, by path.",
	}, []string{"path"})
)
