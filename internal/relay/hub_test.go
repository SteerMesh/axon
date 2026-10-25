package relay

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestHubForwardsOpaquePayload(t *testing.T) {
	hub := NewHub("test-token")
	server := httptest.NewServer(hub)
	defer server.Close()
	base := "ws" + strings.TrimPrefix(server.URL, "http") + "/v1/connect?mate_id=mate-1"
	header := make(http.Header)
	header.Set("Authorization", "Bearer test-token")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	mate, _, err := websocket.Dial(ctx, base+"&role=mate", &websocket.DialOptions{HTTPHeader: header})
	if err != nil {
		t.Fatal(err)
	}
	defer mate.CloseNow()
	device, _, err := websocket.Dial(ctx, base+"&role=device&device_id=device-1", &websocket.DialOptions{HTTPHeader: header})
	if err != nil {
		t.Fatal(err)
	}
	defer device.CloseNow()
	payload := []byte{0, 1, 2, 255}
	encoded, _ := json.Marshal(RouteFrame{Version: 1, MateID: "mate-1", Payload: payload})
	if err := device.Write(ctx, websocket.MessageBinary, encoded); err != nil {
		t.Fatal(err)
	}
	_, received, err := mate.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var frame RouteFrame
	if err := json.Unmarshal(received, &frame); err != nil {
		t.Fatal(err)
	}
	if frame.From != "device-1" || frame.To != "mate" || string(frame.Payload) != string(payload) {
		t.Fatalf("unexpected forwarded frame: %+v", frame)
	}
}

func TestHubAcceptsBrowserSubprotocolAuthentication(t *testing.T) {
	hub := NewHub("browser-token")
	server := httptest.NewServer(hub)
	defer server.Close()
	url := "ws" + strings.TrimPrefix(server.URL, "http") + "/v1/connect?mate_id=mate-1&role=device&device_id=browser"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tokenProtocol := "bearer." + base64.RawURLEncoding.EncodeToString([]byte("browser-token"))
	conn, response, err := websocket.Dial(ctx, url, &websocket.DialOptions{Subprotocols: []string{"axon.v1", tokenProtocol}})
	if err != nil {
		t.Fatalf("browser-style authentication failed (status %v): %v", response.StatusCode, err)
	}
	defer conn.CloseNow()
	if conn.Subprotocol() != "axon.v1" {
		t.Fatalf("unexpected negotiated subprotocol %q", conn.Subprotocol())
	}
}

func TestHubHTTPValidation(t *testing.T) {
	hub := NewHub("token")
	server := httptest.NewServer(hub)
	defer server.Close()
	for _, test := range []struct {
		path   string
		status int
	}{
		{"/healthz", http.StatusOK},
		{"/missing", http.StatusNotFound},
		{"/v1/connect", http.StatusUnauthorized},
		{"/v1/connect?mate_id=mate&role=invalid", http.StatusUnauthorized},
	} {
		response, err := http.Get(server.URL + test.path)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != test.status {
			t.Fatalf("%s status=%d", test.path, response.StatusCode)
		}
	}
	request, _ := http.NewRequest(http.MethodGet, server.URL+"/v1/connect?mate_id=mate&role=invalid", nil)
	request.Header.Set("Authorization", "Bearer token")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid identity status=%d", response.StatusCode)
	}
}

func TestHubForwardsMateToDevice(t *testing.T) {
	hub := NewHub("test-token")
	server := httptest.NewServer(hub)
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	mate := dialPeer(t, ctx, server.URL, "mate-1", "mate", "")
	defer mate.CloseNow()
	device := dialPeer(t, ctx, server.URL, "mate-1", "device", "device-1")
	defer device.CloseNow()
	encoded, _ := json.Marshal(RouteFrame{Version: 1, MateID: "mate-1", To: "device-1", Payload: []byte("reply")})
	if err := mate.Write(ctx, websocket.MessageBinary, encoded); err != nil {
		t.Fatal(err)
	}
	_, received, err := device.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var frame RouteFrame
	if err := json.Unmarshal(received, &frame); err != nil || frame.From != "mate" || string(frame.Payload) != "reply" {
		t.Fatalf("frame=%+v err=%v", frame, err)
	}
}

func TestHubKeepsMateConnectedWhenDeviceDeliveryFails(t *testing.T) {
	hub := NewHub("test-token")
	server := httptest.NewServer(hub)
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	mate := dialPeer(t, ctx, server.URL, "mate-1", "mate", "")
	defer mate.CloseNow()
	closedConn := dialPeer(t, ctx, server.URL, "throwaway", "device", "throwaway")
	closedConn.CloseNow()
	stale := &peer{conn: closedConn, mateID: "mate-1", deviceID: "stale", role: "device"}
	if err := hub.register(stale); err != nil {
		t.Fatal(err)
	}

	failedDelivery, _ := json.Marshal(RouteFrame{
		Version: 1, MateID: "mate-1", To: "stale", Payload: []byte("undeliverable"),
	})
	if err := mate.Write(ctx, websocket.MessageBinary, failedDelivery); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for hub.target(RouteFrame{MateID: "mate-1", To: "stale"}) != nil && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if hub.target(RouteFrame{MateID: "mate-1", To: "stale"}) != nil {
		t.Fatal("failed device remained registered")
	}

	live := dialPeer(t, ctx, server.URL, "mate-1", "device", "live")
	defer live.CloseNow()
	fromDevice, _ := json.Marshal(RouteFrame{Version: 1, MateID: "mate-1", Payload: []byte("still-connected")})
	if err := live.Write(ctx, websocket.MessageBinary, fromDevice); err != nil {
		t.Fatal(err)
	}
	_, received, err := mate.Read(ctx)
	if err != nil {
		t.Fatalf("mate was disconnected after stale device delivery: %v", err)
	}
	var frame RouteFrame
	if err := json.Unmarshal(received, &frame); err != nil || string(frame.Payload) != "still-connected" {
		t.Fatalf("frame=%+v err=%v", frame, err)
	}
}

func TestHubRegistrationAndInvalidFrames(t *testing.T) {
	hub := NewHub("token")
	mate := &peer{mateID: "mate", role: "mate"}
	if err := hub.register(mate); err != nil {
		t.Fatal(err)
	}
	if err := hub.register(&peer{mateID: "mate", role: "mate"}); err == nil {
		t.Fatal("duplicate mate accepted")
	}
	device := &peer{mateID: "mate", deviceID: "device", role: "device"}
	if err := hub.register(device); err != nil {
		t.Fatal(err)
	}
	if err := hub.register(&peer{mateID: "mate", deviceID: "device", role: "device"}); err == nil {
		t.Fatal("duplicate device accepted")
	}
	if hub.target(RouteFrame{MateID: "mate", To: "device"}) != device {
		t.Fatal("device target not resolved")
	}
	hub.unregister(device)
	hub.unregister(mate)

	server := httptest.NewServer(NewHub("token"))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn := dialPeer(t, ctx, server.URL, "mate", "device", "device")
	if err := conn.Write(ctx, websocket.MessageText, []byte("text")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := conn.Read(ctx); err == nil {
		t.Fatal("text frame did not close connection")
	}
	conn.CloseNow()

	conn = dialPeer(t, ctx, server.URL, "mate", "device", "device")
	if err := conn.Write(ctx, websocket.MessageBinary, []byte("not-json")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := conn.Read(ctx); err == nil {
		t.Fatal("invalid frame did not close connection")
	}
	conn.CloseNow()
}

func dialPeer(t *testing.T, ctx context.Context, serverURL, mateID, role, deviceID string) *websocket.Conn {
	t.Helper()
	url := "ws" + strings.TrimPrefix(serverURL, "http") + "/v1/connect?mate_id=" + mateID + "&role=" + role
	if deviceID != "" {
		url += "&device_id=" + deviceID
	}
	header := make(http.Header)
	header.Set("Authorization", "Bearer test-token")
	if strings.Contains(serverURL, "127.0.0.1") {
		// The helper is also used by token-specific tests below.
		header.Set("Authorization", "Bearer token")
	}
	conn, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{HTTPHeader: header})
	if err != nil {
		// Retry with the forwarding-test token.
		header.Set("Authorization", "Bearer test-token")
		conn, _, err = websocket.Dial(ctx, url, &websocket.DialOptions{HTTPHeader: header})
	}
	if err != nil {
		t.Fatal(err)
	}
	return conn
}
