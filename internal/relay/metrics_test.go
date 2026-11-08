package relay

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/SteerMesh/axon/internal/security"
	"github.com/coder/websocket"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestMetricsSurviveRepeatedHubConstruction guards against the classic
// promauto/MustRegister pitfall: registering a collector every time a Hub
// is built, rather than once at package load. internal/relay's own suite
// (hub_test.go, hub_push_test.go) already constructs dozens of Hubs in this
// same test binary; if metrics.go ever regresses to registering inside
// NewHub, this is where it would panic first.
func TestMetricsSurviveRepeatedHubConstruction(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("constructing multiple Hubs panicked (likely duplicate metrics registration): %v", r)
		}
	}()
	for i := 0; i < 5; i++ {
		mate := newTestMate(t, "mate-metrics")
		_ = NewHub(mate.keys())
	}
}

// TestConnectionsActiveGaugeTracksRegisterUnregister exercises a real
// connect/disconnect through the Hub's public HTTP surface (not by calling
// register/unregister directly) and asserts axon_relay_connections_active
// moves by exactly the expected delta for each role. Deltas, not absolute
// values, are asserted because the gauge is a package-level collector
// shared across every test in this binary -- asserting an absolute value
// would make this test's result depend on execution order relative to
// every other test that connects a peer.
func TestConnectionsActiveGaugeTracksRegisterUnregister(t *testing.T) {
	mate := newTestMate(t, "mate-gauge")
	hub := NewHub(mate.keys())
	server := httptest.NewServer(hub)
	defer server.Close()
	base := "ws" + strings.TrimPrefix(server.URL, "http") + "/v1/connect?mate_id=mate-gauge"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	mateBefore := testutil.ToFloat64(connectionsActive.WithLabelValues("mate"))

	mateHeader := make(http.Header)
	mateHeader.Set("Authorization", "Bearer "+mate.mint(t, security.RelayScopeMate, "", time.Minute))
	mateConn, _, err := websocket.Dial(ctx, base+"&role=mate", &websocket.DialOptions{HTTPHeader: mateHeader})
	if err != nil {
		t.Fatal(err)
	}

	deviceBefore := testutil.ToFloat64(connectionsActive.WithLabelValues("device"))

	deviceHeader := make(http.Header)
	deviceHeader.Set("Authorization", "Bearer "+mate.mint(t, security.RelayScopeDevice, "device-1", time.Minute))
	device, _, err := websocket.Dial(ctx, base+"&role=device&device_id=device-1", &websocket.DialOptions{HTTPHeader: deviceHeader})
	if err != nil {
		t.Fatal(err)
	}

	if got := testutil.ToFloat64(connectionsActive.WithLabelValues("mate")); got != mateBefore+1 {
		t.Fatalf("mate gauge after connect = %v, want %v", got, mateBefore+1)
	}
	if got := testutil.ToFloat64(connectionsActive.WithLabelValues("device")); got != deviceBefore+1 {
		t.Fatalf("device gauge after connect = %v, want %v", got, deviceBefore+1)
	}

	mateConn.CloseNow()
	device.CloseNow()
	// Disconnection is detected by the server's readLoop on its next
	// Read, which runs in a goroutine the client-side CloseNow doesn't
	// wait on. Poll instead of sleeping a fixed duration.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if testutil.ToFloat64(connectionsActive.WithLabelValues("mate")) == mateBefore &&
			testutil.ToFloat64(connectionsActive.WithLabelValues("device")) == deviceBefore {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("gauges did not return to pre-test baseline after disconnect: mate=%v device=%v want mate=%v device=%v",
		testutil.ToFloat64(connectionsActive.WithLabelValues("mate")),
		testutil.ToFloat64(connectionsActive.WithLabelValues("device")),
		mateBefore, deviceBefore)
}

// TestAuthFailureReasonMapping pins authFailureReason's classification to
// the exact sentinel errors security.VerifyRelayToken can actually return
// (see relaytoken.go) -- it must not invent a label VerifyRelayToken has no
// branch for.
func TestAuthFailureReasonMapping(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"wrong scope", security.ErrRelayTokenWrongScope, "wrong_scope"},
		{"device id mismatch", security.ErrRelayTokenDeviceMismatch, "device_id_mismatch"},
		{"expired", security.ErrRelayTokenExpired, "expired"},
		{"invalid/malformed", security.ErrRelayTokenInvalid, "bad_signature"},
		{"wrapped invalid", errors.New("wrap: " + security.ErrRelayTokenInvalid.Error()), "bad_signature"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := authFailureReason(test.err); got != test.want {
				t.Fatalf("authFailureReason(%v) = %q, want %q", test.err, got, test.want)
			}
		})
	}
}

// TestAuthFailuresCounterIncrementsOnRejection drives real rejected
// /v1/connect attempts through the Hub's HTTP surface and asserts the
// unknown_mate and bad_signature reasons each increment
// axon_relay_auth_failures_total, exercising the wiring in
// verifyRelayAccessToken end to end rather than just the label function.
func TestAuthFailuresCounterIncrementsOnRejection(t *testing.T) {
	mate := newTestMate(t, "mate-auth")
	hub := NewHub(mate.keys())
	server := httptest.NewServer(hub)
	defer server.Close()

	unknownBefore := testutil.ToFloat64(authFailures.WithLabelValues("unknown_mate"))
	resp, err := http.Get(server.URL + "/v1/connect?mate_id=nobody&role=mate")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if got := testutil.ToFloat64(authFailures.WithLabelValues("unknown_mate")); got != unknownBefore+1 {
		t.Fatalf("unknown_mate counter = %v, want %v", got, unknownBefore+1)
	}

	badSigBefore := testutil.ToFloat64(authFailures.WithLabelValues("bad_signature"))
	request, _ := http.NewRequest(http.MethodGet, server.URL+"/v1/connect?mate_id=mate-auth&role=mate", nil)
	resp, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if got := testutil.ToFloat64(authFailures.WithLabelValues("bad_signature")); got != badSigBefore+1 {
		t.Fatalf("bad_signature counter (missing token) = %v, want %v", got, badSigBefore+1)
	}
}

// TestFramesAndPushMetricsCoverTheThreeOutcomes exercises each of the three
// axon_relay_frames_total delivery outcomes readLoop already distinguished
// before this change (delivered, dropped_no_peer, woken_via_push) through
// real connections, and asserts each increments its corresponding counter
// label. This hub never calls EnablePush, so its woken_via_push case stops
// at triggerPush's own "push not configured" early return and never reaches
// notify() -- it does not exercise axon_relay_push_total. That metric's
// sent/failed/pruned outcomes are covered separately, with push actually
// enabled, by TestHubTriggerPushKeepsSubscriptionOnSuccess,
// TestHubTriggerPushIgnoresSendError, and the two
// TestHubTriggerPushDeletesSubscriptionOn*Response tests in
// hub_push_test.go.
func TestFramesAndPushMetricsCoverTheThreeOutcomes(t *testing.T) {
	mate := newTestMate(t, "mate-frames")
	hub := NewHub(mate.keys())
	server := httptest.NewServer(hub)
	defer server.Close()
	base := "ws" + strings.TrimPrefix(server.URL, "http") + "/v1/connect?mate_id=mate-frames"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	mateHeader := make(http.Header)
	mateHeader.Set("Authorization", "Bearer "+mate.mint(t, security.RelayScopeMate, "", time.Minute))
	mateConn, _, err := websocket.Dial(ctx, base+"&role=mate", &websocket.DialOptions{HTTPHeader: mateHeader})
	if err != nil {
		t.Fatal(err)
	}
	defer mateConn.CloseNow()

	deviceHeader := make(http.Header)
	deviceHeader.Set("Authorization", "Bearer "+mate.mint(t, security.RelayScopeDevice, "device-1", time.Minute))
	device, _, err := websocket.Dial(ctx, base+"&role=device&device_id=device-1", &websocket.DialOptions{HTTPHeader: deviceHeader})
	if err != nil {
		t.Fatal(err)
	}
	defer device.CloseNow()

	deliveredBefore := testutil.ToFloat64(framesTotal.WithLabelValues("delivered"))
	payload := []byte{1, 2, 3}
	encoded, _ := json.Marshal(RouteFrame{Version: 1, MateID: "mate-frames", Payload: payload})
	if err := device.Write(ctx, websocket.MessageBinary, encoded); err != nil {
		t.Fatal(err)
	}
	if _, _, err := mateConn.Read(ctx); err != nil {
		t.Fatal(err)
	}
	if got := testutil.ToFloat64(framesTotal.WithLabelValues("delivered")); got != deliveredBefore+1 {
		t.Fatalf("delivered counter = %v, want %v", got, deliveredBefore+1)
	}

	// mate -> an offline device: no connected peer, so this falls into
	// the Web Push wake path.
	wokenBefore := testutil.ToFloat64(framesTotal.WithLabelValues("woken_via_push"))
	toOffline, _ := json.Marshal(RouteFrame{Version: 1, MateID: "mate-frames", To: "device-offline", Payload: payload})
	if err := mateConn.Write(ctx, websocket.MessageBinary, toOffline); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && testutil.ToFloat64(framesTotal.WithLabelValues("woken_via_push")) == wokenBefore {
		time.Sleep(5 * time.Millisecond)
	}
	if got := testutil.ToFloat64(framesTotal.WithLabelValues("woken_via_push")); got != wokenBefore+1 {
		t.Fatalf("woken_via_push counter = %v, want %v", got, wokenBefore+1)
	}

	// device -> no mate connected: dropped_no_peer, verified on a
	// separate hub/connection so the still-connected mate above doesn't
	// interfere.
	droppedMate := newTestMate(t, "mate-dropped")
	droppedHub := NewHub(droppedMate.keys())
	droppedServer := httptest.NewServer(droppedHub)
	defer droppedServer.Close()
	droppedBase := "ws" + strings.TrimPrefix(droppedServer.URL, "http") + "/v1/connect?mate_id=mate-dropped&role=device&device_id=device-1"
	droppedHeader := make(http.Header)
	droppedHeader.Set("Authorization", "Bearer "+droppedMate.mint(t, security.RelayScopeDevice, "device-1", time.Minute))
	droppedDevice, _, err := websocket.Dial(ctx, droppedBase, &websocket.DialOptions{HTTPHeader: droppedHeader})
	if err != nil {
		t.Fatal(err)
	}
	defer droppedDevice.CloseNow()

	droppedBefore := testutil.ToFloat64(framesTotal.WithLabelValues("dropped_no_peer"))
	droppedFrame, _ := json.Marshal(RouteFrame{Version: 1, MateID: "mate-dropped", Payload: payload})
	_ = droppedDevice.Write(ctx, websocket.MessageBinary, droppedFrame)
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && testutil.ToFloat64(framesTotal.WithLabelValues("dropped_no_peer")) == droppedBefore {
		time.Sleep(5 * time.Millisecond)
	}
	if got := testutil.ToFloat64(framesTotal.WithLabelValues("dropped_no_peer")); got != droppedBefore+1 {
		t.Fatalf("dropped_no_peer counter = %v, want %v", got, droppedBefore+1)
	}
}

// TestMetricsEndpointServesPrometheusTextFormat confirms promhttp.Handler()
// (the exact handler cmd/axon-relay/main.go mounts on
// AXON_RELAY_METRICS_ADDR) serves the metrics this package registers, in
// Prometheus text exposition format, from the default registry.
func TestMetricsEndpointServesPrometheusTextFormat(t *testing.T) {
	// Touch every metric so each is guaranteed to appear in the default
	// registry's gather output regardless of what other tests in this
	// binary have already exercised.
	connectionsActive.WithLabelValues("mate").Add(0)
	authFailures.WithLabelValues("unknown_mate").Add(0)
	framesTotal.WithLabelValues("delivered").Add(0)
	frameBytes.Observe(0)
	pushTotal.WithLabelValues("sent").Add(0)
	rateLimitedTotal.WithLabelValues("/v1/connect").Add(0)

	server := httptest.NewServer(promhttp.Handler())
	defer server.Close()

	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/plain") {
		t.Fatalf("unexpected content type: %s", ct)
	}
	body := make([]byte, 0, 64<<10)
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		body = append(body, buf[:n]...)
		if err != nil {
			break
		}
	}
	text := string(body)
	for _, want := range []string{
		"axon_relay_connections_active",
		"axon_relay_auth_failures_total",
		"axon_relay_frames_total",
		"axon_relay_frame_bytes",
		"axon_relay_push_total",
		"axon_relay_rate_limited_total",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("metrics output missing %q", want)
		}
	}
}
