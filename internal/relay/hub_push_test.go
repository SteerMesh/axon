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
	"github.com/coder/websocket"
)

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
	hub := NewHub("token")
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
	hub := NewHub("token")
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
	hub := NewHub("token")
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

func TestPushSubscribeReturns503WhenNotConfigured(t *testing.T) {
	hub := NewHub("token")
	server := httptest.NewServer(hub)
	defer server.Close()

	request, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/push/subscribe", bytes.NewReader([]byte(`{}`)))
	request.Header.Set("Authorization", "Bearer token")
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
	hub := NewHub("token")
	hub.EnablePush(store, "pub", "priv")
	server := httptest.NewServer(hub)
	defer server.Close()

	payload, _ := json.Marshal(map[string]any{
		"mate_id": "mate-1", "device_id": "device-1", "endpoint": "https://push.example/ep",
		"keys": map[string]string{"p256dh": "p256", "auth": "auth"},
	})
	request, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/push/subscribe", bytes.NewReader(payload))
	request.Header.Set("Authorization", "Bearer token")
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
	deleteRequest.Header.Set("Authorization", "Bearer token")
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
	hub := NewHub("token")
	hub.EnablePush(store, "pub", "priv")
	server := httptest.NewServer(hub)
	defer server.Close()

	body, _ := json.Marshal(map[string]string{"mate_id": "mate-1", "device_id": "device-1"})
	deleteRequest, _ := http.NewRequest(http.MethodDelete, server.URL+"/v1/push/subscribe", bytes.NewReader(body))
	deleteRequest.Header.Set("Authorization", "Bearer token")
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
	hub := NewHub("token")
	hub.EnablePush(newTestSubscriptionStore(t), "pub", "priv")
	server := httptest.NewServer(hub)
	defer server.Close()

	request, _ := http.NewRequest(http.MethodGet, server.URL+"/v1/push/subscribe", nil)
	request.Header.Set("Authorization", "Bearer token")
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
	hub := NewHub("token")
	hub.EnablePush(newTestSubscriptionStore(t), "pub", "priv")
	server := httptest.NewServer(hub)
	defer server.Close()

	request, _ := http.NewRequest(http.MethodDelete, server.URL+"/v1/push/subscribe", bytes.NewReader([]byte(`{}`)))
	request.Header.Set("Authorization", "Bearer token")
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
	hub := NewHub("token")
	hub.EnablePush(store, "pub", "priv")
	server := httptest.NewServer(hub)
	defer server.Close()
	_ = store.Close() // force subsequent store operations to fail

	payload, _ := json.Marshal(map[string]any{
		"mate_id": "mate-1", "device_id": "device-1", "endpoint": "https://push.example/ep",
		"keys": map[string]string{"p256dh": "p", "auth": "a"},
	})
	request, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/push/subscribe", bytes.NewReader(payload))
	request.Header.Set("Authorization", "Bearer token")
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
	hub := NewHub("token")
	hub.EnablePush(store, "pub", "priv")
	server := httptest.NewServer(hub)
	defer server.Close()
	_ = store.Close() // force subsequent store operations to fail

	request, _ := http.NewRequest(http.MethodDelete, server.URL+"/v1/push/subscribe?mate_id=mate-1&device_id=device-1", nil)
	request.Header.Set("Authorization", "Bearer token")
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
	hub := NewHub("token")
	hub.EnablePush(newTestSubscriptionStore(t), "pub", "priv")
	server := httptest.NewServer(hub)
	defer server.Close()

	payload, _ := json.Marshal(map[string]any{"mate_id": "mate-1"})
	request, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/push/subscribe", bytes.NewReader(payload))
	request.Header.Set("Authorization", "Bearer token")
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
	hub := NewHub("token")
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
	hub := NewHub("token")
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
	hub := NewHub("token")
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
	hub := NewHub("token")
	hub.EnablePush(store, "pub", "priv")
	hub.push.send = func(ctx context.Context, message []byte, s *webpush.Subscription, options *webpush.Options) (*http.Response, error) {
		return fakeResponse(http.StatusGone), nil
	}

	hub.triggerPush(RouteFrame{MateID: "mate-1", To: "device-1"})

	deadline := time.Now().Add(2 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		if _, err := store.Get(context.Background(), "mate-1", "device-1"); err != nil {
			lastErr = err
			if errors.Is(err, sql.ErrNoRows) {
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
	hub := NewHub("token")
	hub.EnablePush(store, "pub", "priv")
	hub.push.send = func(ctx context.Context, message []byte, s *webpush.Subscription, options *webpush.Options) (*http.Response, error) {
		return fakeResponse(http.StatusNotFound), nil
	}

	hub.triggerPush(RouteFrame{MateID: "mate-1", To: "device-1"})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := store.Get(context.Background(), "mate-1", "device-1"); errors.Is(err, sql.ErrNoRows) {
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
	hub := NewHub("token")
	hub.EnablePush(store, "pub", "priv")
	done := make(chan struct{})
	hub.push.send = func(ctx context.Context, message []byte, s *webpush.Subscription, options *webpush.Options) (*http.Response, error) {
		defer close(done)
		return fakeResponse(http.StatusCreated), nil
	}

	hub.triggerPush(RouteFrame{MateID: "mate-1", To: "device-1"})

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("push was not attempted")
	}
	time.Sleep(20 * time.Millisecond)
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
	hub := NewHub("token")
	hub.EnablePush(store, "pub", "priv")
	done := make(chan struct{})
	hub.push.send = func(ctx context.Context, message []byte, s *webpush.Subscription, options *webpush.Options) (*http.Response, error) {
		defer close(done)
		return nil, errors.New("push service unreachable")
	}

	hub.triggerPush(RouteFrame{MateID: "mate-1", To: "device-1"})

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("push send was not attempted")
	}
	// A transient send error must not drop the subscription -- only a
	// 404/410 response from the push service does that.
	time.Sleep(20 * time.Millisecond)
	if _, err := store.Get(context.Background(), "mate-1", "device-1"); err != nil {
		t.Fatalf("subscription should survive a transient send error: %v", err)
	}
}

func TestHubTriggerPushLookupErrorIsNotTreatedAsMissing(t *testing.T) {
	store := newTestSubscriptionStore(t)
	hub := NewHub("token")
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
	hub := NewHub("test-token")
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
	mate := dialPeer(t, ctx, server.URL, "mate-1", "mate", "")
	defer mate.CloseNow()

	// device-1 never connects, so the mate's frame to it has no target peer.
	encoded, _ := json.Marshal(RouteFrame{Version: 1, MateID: "mate-1", To: "device-1", Payload: []byte("secret")})
	if err := mate.Write(ctx, websocket.MessageBinary, encoded); err != nil {
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
