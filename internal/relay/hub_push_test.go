package relay

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	webpush "github.com/SherClockHolmes/webpush-go"
	"github.com/SteerMesh/axon/internal/security"
	"github.com/coder/websocket"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// waitForCounterDelta polls counter (a single-label-value Counter obtained
// via WithLabelValues) until it reaches baseline+delta, or fails the test.
// notify() runs in a goroutine spawned by triggerPush, so the metric
// increment races with the test goroutine's own progress -- polling with a
// timeout, rather than asserting immediately after a channel receive or a
// fixed sleep, is what makes these assertions deterministic instead of
// occasionally flaky.
func waitForCounterDelta(t *testing.T, counter prometheus.Counter, baseline, delta float64) {
	t.Helper()
	want := baseline + delta
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got := testutil.ToFloat64(counter); got == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("counter = %v, want %v", testutil.ToFloat64(counter), want)
}

func newTestSubscriptionStore(t *testing.T) *SubscriptionStore {
	t.Helper()
	store, err := OpenSubscriptionStore(filepath.Join(t.TempDir(), "push.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func fakeResponse(status int) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(""))}
}

func TestVAPIDKeyEndpointUnauthenticated(t *testing.T) {
	hub := NewHub(nil)
	hub.EnablePush(newTestSubscriptionStore(t), "the-public-key", "the-private-key")
	server := httptest.NewServer(hub)
	defer server.Close()

	response, err := http.Get(server.URL + "/v1/vapid-key")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", response.StatusCode)
	}
	var body map[string]string
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["publicKey"] != "the-public-key" {
		t.Fatalf("unexpected body: %+v", body)
	}
}

func TestVAPIDKeyEndpointEmptyWhenPushDisabled(t *testing.T) {
	hub := NewHub(nil)
	server := httptest.NewServer(hub)
	defer server.Close()

	response, err := http.Get(server.URL + "/v1/vapid-key")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var body map[string]string
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["publicKey"] != "" {
		t.Fatalf("expected empty public key, got %+v", body)
	}
}

func TestPushSubscribeRequiresAuth(t *testing.T) {
	hub := NewHub(nil)
	hub.EnablePush(newTestSubscriptionStore(t), "pub", "priv")
	server := httptest.NewServer(hub)
	defer server.Close()

	body, _ := json.Marshal(map[string]any{
		"mate_id": "mate-1", "device_id": "device-1", "endpoint": "https://push.example/ep",
		"keys": map[string]string{"p256dh": "p", "auth": "a"},
	})
	response, err := http.Post(server.URL+"/v1/push/subscribe", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d", response.StatusCode)
	}
}

// TestPushSubscribeRejectsNonDeviceScopedTokens is the scope-confusion
// regression this feature exists to prevent: a pairing-scope token (valid
// before a device's real ID is known, and wildcarded to any device_id) or
// a mate-scope token must not authorize push subscribe/unsubscribe, even
// though both are perfectly valid tokens signed by a registered mate. Only
// a device-scope token -- which a device only holds once pairing has
// actually completed -- is accepted (see authorizedDevice).
func TestPushSubscribeRejectsNonDeviceScopedTokens(t *testing.T) {
	mate := newTestMate(t, "mate-1")
	hub := NewHub(mate.keys())
	hub.EnablePush(newTestSubscriptionStore(t), "pub", "priv")
	server := httptest.NewServer(hub)
	defer server.Close()

	payload, _ := json.Marshal(map[string]any{
		"mate_id": "mate-1", "device_id": "device-1", "endpoint": "https://push.example/ep",
		"keys": map[string]string{"p256dh": "p", "auth": "a"},
	})

	for _, test := range []struct {
		name  string
		token string
	}{
		{"pairing-scope token, wildcard device_id", mate.mint(t, security.RelayScopePairing, "", time.Minute)},
		{"pairing-scope token, matching device_id", mate.mint(t, security.RelayScopePairing, "device-1", time.Minute)},
		{"mate-scope token", mate.mint(t, security.RelayScopeMate, "", time.Minute)},
	} {
		t.Run(test.name, func(t *testing.T) {
			postRequest, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/push/subscribe", bytes.NewReader(payload))
			postRequest.Header.Set("Authorization", "Bearer "+test.token)
			postResponse, err := http.DefaultClient.Do(postRequest)
			if err != nil {
				t.Fatal(err)
			}
			_ = postResponse.Body.Close()
			if postResponse.StatusCode != http.StatusUnauthorized {
				t.Fatalf("POST status=%d, want %d", postResponse.StatusCode, http.StatusUnauthorized)
			}

			deleteRequest, _ := http.NewRequest(http.MethodDelete, server.URL+"/v1/push/subscribe?mate_id=mate-1&device_id=device-1", nil)
			deleteRequest.Header.Set("Authorization", "Bearer "+test.token)
			deleteResponse, err := http.DefaultClient.Do(deleteRequest)
			if err != nil {
				t.Fatal(err)
			}
			_ = deleteResponse.Body.Close()
			if deleteResponse.StatusCode != http.StatusUnauthorized {
				t.Fatalf("DELETE status=%d, want %d", deleteResponse.StatusCode, http.StatusUnauthorized)
			}
		})
	}
}

func TestPushSubscribeReturns503WhenNotConfigured(t *testing.T) {
	hub := NewHub(nil)
	server := httptest.NewServer(hub)
	defer server.Close()

	// Push isn't configured, so the 503 fires before identity/auth is even
	// parsed -- no Authorization header is needed to reach it.
	request, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/push/subscribe", bytes.NewReader([]byte(`{}`)))
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status=%d", response.StatusCode)
	}
}

func TestPushSubscribePostUpsertsAndDeleteRemoves(t *testing.T) {
	store := newTestSubscriptionStore(t)
	mate := newTestMate(t, "mate-1")
	hub := NewHub(mate.keys())
	hub.EnablePush(store, "pub", "priv")
	server := httptest.NewServer(hub)
	defer server.Close()
	// By the time a device calls push subscribe, pairing has already
	// completed and it holds a real device-scope token (see
	// security.PairingResult) -- that's the only scope authorizedDevice
	// accepts here.
	deviceToken := mate.mint(t, security.RelayScopeDevice, "device-1", time.Minute)

	payload, _ := json.Marshal(map[string]any{
		"mate_id": "mate-1", "device_id": "device-1", "endpoint": "https://push.example/ep",
		"keys": map[string]string{"p256dh": "p256", "auth": "auth"},
	})
	request, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/push/subscribe", bytes.NewReader(payload))
	request.Header.Set("Authorization", "Bearer "+deviceToken)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("status=%d", response.StatusCode)
	}
	stored, err := store.Get(context.Background(), "mate-1", "device-1")
	if err != nil || stored.Endpoint != "https://push.example/ep" {
		t.Fatalf("subscription not stored: %+v err=%v", stored, err)
	}

	deleteRequest, _ := http.NewRequest(http.MethodDelete, server.URL+"/v1/push/subscribe?mate_id=mate-1&device_id=device-1", nil)
	deleteRequest.Header.Set("Authorization", "Bearer "+deviceToken)
	deleteResponse, err := http.DefaultClient.Do(deleteRequest)
	if err != nil {
		t.Fatal(err)
	}
	_ = deleteResponse.Body.Close()
	if deleteResponse.StatusCode != http.StatusNoContent {
		t.Fatalf("delete status=%d", deleteResponse.StatusCode)
	}
	if _, err := store.Get(context.Background(), "mate-1", "device-1"); err == nil {
		t.Fatal("subscription was not deleted")
	}
}

func TestPushSubscribeDeleteByBody(t *testing.T) {
	store := newTestSubscriptionStore(t)
	if err := store.Upsert(context.Background(), Subscription{MateID: "mate-1", DeviceID: "device-1", Endpoint: "e", P256dh: "p", Auth: "a", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	mate := newTestMate(t, "mate-1")
	hub := NewHub(mate.keys())
	hub.EnablePush(store, "pub", "priv")
	server := httptest.NewServer(hub)
	defer server.Close()

	body, _ := json.Marshal(map[string]string{"mate_id": "mate-1", "device_id": "device-1"})
	deleteRequest, _ := http.NewRequest(http.MethodDelete, server.URL+"/v1/push/subscribe", bytes.NewReader(body))
	deleteRequest.Header.Set("Authorization", "Bearer "+mate.mint(t, security.RelayScopeDevice, "device-1", time.Minute))
	response, err := http.DefaultClient.Do(deleteRequest)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("status=%d", response.StatusCode)
	}
	if _, err := store.Get(context.Background(), "mate-1", "device-1"); err == nil {
		t.Fatal("subscription was not deleted")
	}
}

func TestPushSubscribeMethodNotAllowed(t *testing.T) {
	hub := NewHub(nil)
	hub.EnablePush(newTestSubscriptionStore(t), "pub", "priv")
	server := httptest.NewServer(hub)
	defer server.Close()

	// GET falls straight to "method not allowed" -- no identity to parse,
	// so no Authorization header is needed to reach it.
	request, _ := http.NewRequest(http.MethodGet, server.URL+"/v1/push/subscribe", nil)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d", response.StatusCode)
	}
}

func TestPushSubscribeDeleteRequiresIdentity(t *testing.T) {
	hub := NewHub(nil)
	hub.EnablePush(newTestSubscriptionStore(t), "pub", "priv")
	server := httptest.NewServer(hub)
	defer server.Close()

	// Neither mate_id nor device_id are resolvable from an empty body, so
	// this is a 400 before authorizedDevice is ever called -- no
	// Authorization header is needed to reach it.
	request, _ := http.NewRequest(http.MethodDelete, server.URL+"/v1/push/subscribe", bytes.NewReader([]byte(`{}`)))
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d", response.StatusCode)
	}
}

func TestPushSubscribePostStoreErrorIsSurfaced(t *testing.T) {
	store := newTestSubscriptionStore(t)
	mate := newTestMate(t, "mate-1")
	hub := NewHub(mate.keys())
	hub.EnablePush(store, "pub", "priv")
	server := httptest.NewServer(hub)
	defer server.Close()
	_ = store.Close() // force subsequent store operations to fail

	payload, _ := json.Marshal(map[string]any{
		"mate_id": "mate-1", "device_id": "device-1", "endpoint": "https://push.example/ep",
		"keys": map[string]string{"p256dh": "p", "auth": "a"},
	})
	request, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/push/subscribe", bytes.NewReader(payload))
	request.Header.Set("Authorization", "Bearer "+mate.mint(t, security.RelayScopeDevice, "device-1", time.Minute))
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status=%d", response.StatusCode)
	}
}

func TestPushSubscribeDeleteStoreErrorIsSurfaced(t *testing.T) {
	store := newTestSubscriptionStore(t)
	mate := newTestMate(t, "mate-1")
	hub := NewHub(mate.keys())
	hub.EnablePush(store, "pub", "priv")
	server := httptest.NewServer(hub)
	defer server.Close()
	_ = store.Close() // force subsequent store operations to fail

	request, _ := http.NewRequest(http.MethodDelete, server.URL+"/v1/push/subscribe?mate_id=mate-1&device_id=device-1", nil)
	request.Header.Set("Authorization", "Bearer "+mate.mint(t, security.RelayScopeDevice, "device-1", time.Minute))
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status=%d", response.StatusCode)
	}
}

func TestPushSubscribePostRejectsIncompleteBody(t *testing.T) {
	hub := NewHub(nil)
	hub.EnablePush(newTestSubscriptionStore(t), "pub", "priv")
	server := httptest.NewServer(hub)
	defer server.Close()

	// Missing device_id/endpoint/keys is a 400 before authorizedDevice is
	// ever called -- no Authorization header is needed to reach it.
	payload, _ := json.Marshal(map[string]any{"mate_id": "mate-1"})
	request, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/push/subscribe", bytes.NewReader(payload))
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d", response.StatusCode)
	}
}

// TestHubTriggerPushSendsContentFreePayload is the key security-relevant
// test: the wake notification must carry nothing beyond {"type":"wake"} --
// never sid, data, or anything content-derived from the dropped frame.
func TestHubTriggerPushSendsContentFreePayload(t *testing.T) {
	store := newTestSubscriptionStore(t)
	if err := store.Upsert(context.Background(), Subscription{
		MateID: "mate-1", DeviceID: "device-1", Endpoint: "https://push.example/ep",
		P256dh: "p256dh", Auth: "auth", CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	hub := NewHub(nil)
	hub.EnablePush(store, "pub", "priv")

	sent := make(chan []byte, 1)
	hub.push.send = func(ctx context.Context, message []byte, s *webpush.Subscription, options *webpush.Options) (*http.Response, error) {
		sent <- message
		return fakeResponse(http.StatusCreated), nil
	}

	hub.triggerPush(RouteFrame{
		Version: 1, MateID: "mate-1", To: "device-1",
		Payload: []byte("super secret session bytes"),
	})

	select {
	case payload := <-sent:
		if string(payload) != `{"type":"wake"}` {
			t.Fatalf("push payload leaked content: %s", payload)
		}
		var decoded map[string]any
		if err := json.Unmarshal(payload, &decoded); err != nil {
			t.Fatal(err)
		}
		if len(decoded) != 1 {
			t.Fatalf("push payload has unexpected fields: %+v", decoded)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("push notification was not sent")
	}
}

func TestHubTriggerPushIgnoresMateTargets(t *testing.T) {
	hub := NewHub(nil)
	hub.EnablePush(newTestSubscriptionStore(t), "pub", "priv")
	called := false
	hub.push.send = func(ctx context.Context, message []byte, s *webpush.Subscription, options *webpush.Options) (*http.Response, error) {
		called = true
		return fakeResponse(http.StatusCreated), nil
	}
	hub.triggerPush(RouteFrame{MateID: "mate-1", To: "mate"})
	time.Sleep(20 * time.Millisecond)
	if called {
		t.Fatal("push should never be sent for a mate target")
	}
}

func TestHubTriggerPushNoopWhenNoSubscription(t *testing.T) {
	hub := NewHub(nil)
	hub.EnablePush(newTestSubscriptionStore(t), "pub", "priv")
	called := false
	hub.push.send = func(ctx context.Context, message []byte, s *webpush.Subscription, options *webpush.Options) (*http.Response, error) {
		called = true
		return fakeResponse(http.StatusCreated), nil
	}
	hub.triggerPush(RouteFrame{MateID: "mate-1", To: "device-without-subscription"})
	time.Sleep(20 * time.Millisecond)
	if called {
		t.Fatal("push should not be sent when no subscription is stored")
	}
}

func TestHubTriggerPushDeletesSubscriptionOnGoneResponse(t *testing.T) {
	store := newTestSubscriptionStore(t)
	if err := store.Upsert(context.Background(), Subscription{
		MateID: "mate-1", DeviceID: "device-1", Endpoint: "https://push.example/ep",
		P256dh: "p256dh", Auth: "auth", CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	hub := NewHub(nil)
	hub.EnablePush(store, "pub", "priv")
	hub.push.send = func(ctx context.Context, message []byte, s *webpush.Subscription, options *webpush.Options) (*http.Response, error) {
		return fakeResponse(http.StatusGone), nil
	}
	prunedBefore := testutil.ToFloat64(pushTotal.WithLabelValues("pruned"))

	hub.triggerPush(RouteFrame{MateID: "mate-1", To: "device-1"})

	deadline := time.Now().Add(2 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		if _, err := store.Get(context.Background(), "mate-1", "device-1"); err != nil {
			lastErr = err
			if errors.Is(err, sql.ErrNoRows) {
				waitForCounterDelta(t, pushTotal.WithLabelValues("pruned"), prunedBefore, 1)
				return
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("expired subscription was not deleted after 410 response, last err=%v", lastErr)
}

func TestHubTriggerPushDeletesSubscriptionOnNotFoundResponse(t *testing.T) {
	store := newTestSubscriptionStore(t)
	if err := store.Upsert(context.Background(), Subscription{
		MateID: "mate-1", DeviceID: "device-1", Endpoint: "https://push.example/ep",
		P256dh: "p256dh", Auth: "auth", CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	hub := NewHub(nil)
	hub.EnablePush(store, "pub", "priv")
	hub.push.send = func(ctx context.Context, message []byte, s *webpush.Subscription, options *webpush.Options) (*http.Response, error) {
		return fakeResponse(http.StatusNotFound), nil
	}
	prunedBefore := testutil.ToFloat64(pushTotal.WithLabelValues("pruned"))

	hub.triggerPush(RouteFrame{MateID: "mate-1", To: "device-1"})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := store.Get(context.Background(), "mate-1", "device-1"); errors.Is(err, sql.ErrNoRows) {
			waitForCounterDelta(t, pushTotal.WithLabelValues("pruned"), prunedBefore, 1)
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("dead subscription was not deleted after 404 response")
}

func TestHubTriggerPushKeepsSubscriptionOnSuccess(t *testing.T) {
	store := newTestSubscriptionStore(t)
	if err := store.Upsert(context.Background(), Subscription{
		MateID: "mate-1", DeviceID: "device-1", Endpoint: "https://push.example/ep",
		P256dh: "p256dh", Auth: "auth", CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	hub := NewHub(nil)
	hub.EnablePush(store, "pub", "priv")
	done := make(chan struct{})
	hub.push.send = func(ctx context.Context, message []byte, s *webpush.Subscription, options *webpush.Options) (*http.Response, error) {
		defer close(done)
		return fakeResponse(http.StatusCreated), nil
	}
	sentBefore := testutil.ToFloat64(pushTotal.WithLabelValues("sent"))

	hub.triggerPush(RouteFrame{MateID: "mate-1", To: "device-1"})

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("push was not attempted")
	}
	waitForCounterDelta(t, pushTotal.WithLabelValues("sent"), sentBefore, 1)
	if _, err := store.Get(context.Background(), "mate-1", "device-1"); err != nil {
		t.Fatalf("subscription should survive a successful push: %v", err)
	}
}

func TestHubTriggerPushIgnoresSendError(t *testing.T) {
	store := newTestSubscriptionStore(t)
	if err := store.Upsert(context.Background(), Subscription{
		MateID: "mate-1", DeviceID: "device-1", Endpoint: "https://push.example/ep",
		P256dh: "p256dh", Auth: "auth", CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	hub := NewHub(nil)
	hub.EnablePush(store, "pub", "priv")
	done := make(chan struct{})
	hub.push.send = func(ctx context.Context, message []byte, s *webpush.Subscription, options *webpush.Options) (*http.Response, error) {
		defer close(done)
		return nil, errors.New("push service unreachable")
	}
	failedBefore := testutil.ToFloat64(pushTotal.WithLabelValues("failed"))

	hub.triggerPush(RouteFrame{MateID: "mate-1", To: "device-1"})

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("push send was not attempted")
	}
	waitForCounterDelta(t, pushTotal.WithLabelValues("failed"), failedBefore, 1)
	// A transient send error must not drop the subscription -- only a
	// 404/410 response from the push service does that.
	if _, err := store.Get(context.Background(), "mate-1", "device-1"); err != nil {
		t.Fatalf("subscription should survive a transient send error: %v", err)
	}
}

func TestHubTriggerPushLookupErrorIsNotTreatedAsMissing(t *testing.T) {
	store := newTestSubscriptionStore(t)
	hub := NewHub(nil)
	hub.EnablePush(store, "pub", "priv")
	called := false
	hub.push.send = func(ctx context.Context, message []byte, s *webpush.Subscription, options *webpush.Options) (*http.Response, error) {
		called = true
		return fakeResponse(http.StatusCreated), nil
	}
	_ = store.Close() // any lookup now fails with something other than sql.ErrNoRows

	hub.triggerPush(RouteFrame{MateID: "mate-1", To: "device-1"})
	time.Sleep(20 * time.Millisecond)
	if called {
		t.Fatal("push should not be sent when the subscription lookup itself fails")
	}
}

func TestHubReadLoopTriggersPushWhenDeviceOffline(t *testing.T) {
	store := newTestSubscriptionStore(t)
	if err := store.Upsert(context.Background(), Subscription{
		MateID: "mate-1", DeviceID: "device-1", Endpoint: "https://push.example/ep",
		P256dh: "p256dh", Auth: "auth", CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	mate := newTestMate(t, "mate-1")
	hub := NewHub(mate.keys())
	hub.EnablePush(store, "pub", "priv")
	server := httptest.NewServer(hub)
	defer server.Close()

	sent := make(chan []byte, 1)
	hub.push.send = func(ctx context.Context, message []byte, s *webpush.Subscription, options *webpush.Options) (*http.Response, error) {
		sent <- message
		return fakeResponse(http.StatusCreated), nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	mateConn := dialPeer(t, ctx, server.URL, mate, "mate-1", "mate", "")
	defer mateConn.CloseNow()

	// device-1 never connects, so the mate's frame to it has no target peer.
	encoded, _ := json.Marshal(RouteFrame{Version: 1, MateID: "mate-1", To: "device-1", Payload: []byte("secret")})
	if err := mateConn.Write(ctx, websocket.MessageBinary, encoded); err != nil {
		t.Fatal(err)
	}

	select {
	case payload := <-sent:
		if string(payload) != `{"type":"wake"}` {
			t.Fatalf("push payload leaked content: %s", payload)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("push was not triggered for the offline device")
	}
}
