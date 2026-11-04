package relay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/SteerMesh/axon/internal/security"
	"github.com/coder/websocket"
)

// testMate bundles an identity with the mateKeys map a Hub needs to
// authenticate it, so tests can mint Relay Access Tokens the same way a
// real mate would. Shared with hub_push_test.go (same package).
type testMate struct {
	id       string
	identity security.Identity
}

func newTestMate(t *testing.T, id string) testMate {
	t.Helper()
	identity, err := security.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return testMate{id: id, identity: identity}
}

func (m testMate) keys() map[string]ed25519.PublicKey {
	return map[string]ed25519.PublicKey{m.id: m.identity.SigningPublic}
}

func (m testMate) mint(t *testing.T, scope security.RelayTokenScope, deviceID string, ttl time.Duration) string {
	t.Helper()
	token, _, err := security.MintRelayToken(m.identity, m.id, scope, deviceID, ttl)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestHubForwardsOpaquePayload(t *testing.T) {
	mate := newTestMate(t, "mate-1")
	hub := NewHub(mate.keys())
	server := httptest.NewServer(hub)
	defer server.Close()
	base := "ws" + strings.TrimPrefix(server.URL, "http") + "/v1/connect?mate_id=mate-1"
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

	payload := []byte{0, 1, 2, 255}
	encoded, _ := json.Marshal(RouteFrame{Version: 1, MateID: "mate-1", Payload: payload})
	if err := device.Write(ctx, websocket.MessageBinary, encoded); err != nil {
		t.Fatal(err)
	}
	_, received, err := mateConn.Read(ctx)
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
	mate := newTestMate(t, "mate-1")
	hub := NewHub(mate.keys())
	server := httptest.NewServer(hub)
	defer server.Close()
	url := "ws" + strings.TrimPrefix(server.URL, "http") + "/v1/connect?mate_id=mate-1&role=device&device_id=browser"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	token := mate.mint(t, security.RelayScopePairing, "", time.Minute)
	tokenProtocol := "bearer." + base64.RawURLEncoding.EncodeToString([]byte(token))
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
	mate := newTestMate(t, "mate")
	hub := NewHub(mate.keys())
	server := httptest.NewServer(hub)
	defer server.Close()
	for _, test := range []struct {
		path   string
		status int
	}{
		{"/healthz", http.StatusOK},
		{"/missing", http.StatusNotFound},
		// mate_id/role/device_id are parsed and validated BEFORE
		// authorization runs (see hub.go's ServeHTTP) -- a structurally
		// invalid identity is a 400 even with zero auth attempted.
		{"/v1/connect", http.StatusBadRequest},
		{"/v1/connect?mate_id=mate&role=invalid", http.StatusBadRequest},
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

	// A structurally valid identity with no token at all is unauthorized,
	// not a bad request -- this exercises the auth path, not the
	// identity-shape path above.
	request, _ := http.NewRequest(http.MethodGet, server.URL+"/v1/connect?mate_id=mate&role=mate", nil)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("missing token status=%d", response.StatusCode)
	}
}

// TestHubConnectAuthorizationMatrix exercises authorizedConnect across
// role, scope, device_id match, and expiry -- the exact ordering bug this
// change fixes (mate_id/role/device_id are now parsed before the token is
// verified against them) and the scope rules that replaced the single
// shared static token.
func TestHubConnectAuthorizationMatrix(t *testing.T) {
	mate := newTestMate(t, "mate")
	hub := NewHub(mate.keys())
	server := httptest.NewServer(hub)
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dial := func(mateID, role, deviceID, token string) int {
		url := "ws" + strings.TrimPrefix(server.URL, "http") + "/v1/connect?mate_id=" + mateID + "&role=" + role
		if deviceID != "" {
			url += "&device_id=" + deviceID
		}
		header := make(http.Header)
		if token != "" {
			header.Set("Authorization", "Bearer "+token)
		}
		conn, response, err := websocket.Dial(ctx, url, &websocket.DialOptions{HTTPHeader: header})
		if err == nil {
			conn.CloseNow()
			return http.StatusSwitchingProtocols
		}
		if response == nil {
			t.Fatalf("dial failed with no HTTP response: %v", err)
		}
		return response.StatusCode
	}

	tests := []struct {
		name   string
		mateID string
		role   string
		device string
		token  func() string
		want   int
	}{
		{
			name: "mate-scope token authorizes a mate connection", mateID: "mate", role: "mate",
			token: func() string { return mate.mint(t, security.RelayScopeMate, "", time.Minute) }, want: http.StatusSwitchingProtocols,
		},
		{
			name: "mate-scope token rejected on a device connection", mateID: "mate", role: "device", device: "device-1",
			token: func() string { return mate.mint(t, security.RelayScopeMate, "", time.Minute) }, want: http.StatusUnauthorized,
		},
		{
			name: "device-scope token rejected on a mate connection", mateID: "mate", role: "mate",
			token: func() string { return mate.mint(t, security.RelayScopeDevice, "device-1", time.Minute) }, want: http.StatusUnauthorized,
		},
		{
			name: "device-scope token authorizes its own device_id", mateID: "mate", role: "device", device: "device-1",
			token: func() string { return mate.mint(t, security.RelayScopeDevice, "device-1", time.Minute) }, want: http.StatusSwitchingProtocols,
		},
		{
			name: "device-scope token rejected for a different device_id", mateID: "mate", role: "device", device: "device-2",
			token: func() string { return mate.mint(t, security.RelayScopeDevice, "device-1", time.Minute) }, want: http.StatusUnauthorized,
		},
		{
			name: "pairing-scope wildcard authorizes any device_id", mateID: "mate", role: "device", device: "device-99",
			token: func() string { return mate.mint(t, security.RelayScopePairing, "", time.Minute) }, want: http.StatusSwitchingProtocols,
		},
		{
			name: "expired token rejected", mateID: "mate", role: "mate",
			token: func() string {
				token := mate.mint(t, security.RelayScopeMate, "", time.Nanosecond)
				time.Sleep(10 * time.Millisecond)
				return token
			}, want: http.StatusUnauthorized,
		},
		{
			name: "token for an unregistered mate_id rejected", mateID: "unknown-mate", role: "mate",
			token: func() string { return mate.mint(t, security.RelayScopeMate, "", time.Minute) }, want: http.StatusUnauthorized,
		},
		{
			name: "no token at all", mateID: "mate", role: "mate",
			token: func() string { return "" }, want: http.StatusUnauthorized,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := dial(test.mateID, test.role, test.device, test.token()); got != test.want {
				t.Fatalf("status = %d, want %d", got, test.want)
			}
		})
	}
}

func TestHubForwardsMateToDevice(t *testing.T) {
	mate := newTestMate(t, "mate-1")
	hub := NewHub(mate.keys())
	server := httptest.NewServer(hub)
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	mateConn := dialPeer(t, ctx, server.URL, mate, "mate-1", "mate", "")
	defer mateConn.CloseNow()
	device := dialPeer(t, ctx, server.URL, mate, "mate-1", "device", "device-1")
	defer device.CloseNow()
	encoded, _ := json.Marshal(RouteFrame{Version: 1, MateID: "mate-1", To: "device-1", Payload: []byte("reply")})
	if err := mateConn.Write(ctx, websocket.MessageBinary, encoded); err != nil {
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

// TestHubForwardsFramesLargerThanTheLibraryDefaultReadLimit covers a frame
// between coder/websocket's 32768-byte default read limit and MaxFrameBytes
// (128KiB) — e.g. a session.subscribe reply carrying real scrollback. Without
// Hub.ServeHTTP raising the accepted connection's read limit to match
// MaxFrameBytes, the library kills the connection with StatusMessageTooBig
// before readLoop's own size check ever runs.
func TestHubForwardsFramesLargerThanTheLibraryDefaultReadLimit(t *testing.T) {
	mate := newTestMate(t, "mate-1")
	hub := NewHub(mate.keys())
	server := httptest.NewServer(hub)
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	mateConn := dialPeer(t, ctx, server.URL, mate, "mate-1", "mate", "")
	defer mateConn.CloseNow()
	device := dialPeer(t, ctx, server.URL, mate, "mate-1", "device", "device-1")
	defer device.CloseNow()

	large := bytes.Repeat([]byte("x"), 64*1024)
	encoded, _ := json.Marshal(RouteFrame{Version: 1, MateID: "mate-1", To: "device-1", Payload: large})
	if err := mateConn.Write(ctx, websocket.MessageBinary, encoded); err != nil {
		t.Fatal(err)
	}
	_, received, err := device.Read(ctx)
	if err != nil {
		t.Fatalf("large frame did not arrive: %v", err)
	}
	var frame RouteFrame
	if err := json.Unmarshal(received, &frame); err != nil || len(frame.Payload) != len(large) {
		t.Fatalf("payload truncated or malformed: got %d bytes, err=%v", len(frame.Payload), err)
	}
}

func TestHubKeepsMateConnectedWhenDeviceDeliveryFails(t *testing.T) {
	mate := newTestMate(t, "mate-1")
	hub := NewHub(mate.keys())
	server := httptest.NewServer(hub)
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	mateConn := dialPeer(t, ctx, server.URL, mate, "mate-1", "mate", "")
	defer mateConn.CloseNow()
	closedConn := dialPeer(t, ctx, server.URL, mate, "mate-1", "device", "throwaway")
	closedConn.CloseNow()
	stale := &peer{conn: closedConn, mateID: "mate-1", deviceID: "stale", role: "device"}
	if err := hub.register(stale); err != nil {
		t.Fatal(err)
	}

	failedDelivery, _ := json.Marshal(RouteFrame{
		Version: 1, MateID: "mate-1", To: "stale", Payload: []byte("undeliverable"),
	})
	if err := mateConn.Write(ctx, websocket.MessageBinary, failedDelivery); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for hub.target(RouteFrame{MateID: "mate-1", To: "stale"}) != nil && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if hub.target(RouteFrame{MateID: "mate-1", To: "stale"}) != nil {
		t.Fatal("failed device remained registered")
	}

	live := dialPeer(t, ctx, server.URL, mate, "mate-1", "device", "live")
	defer live.CloseNow()
	fromDevice, _ := json.Marshal(RouteFrame{Version: 1, MateID: "mate-1", Payload: []byte("still-connected")})
	if err := live.Write(ctx, websocket.MessageBinary, fromDevice); err != nil {
		t.Fatal(err)
	}
	_, received, err := mateConn.Read(ctx)
	if err != nil {
		t.Fatalf("mate was disconnected after stale device delivery: %v", err)
	}
	var frame RouteFrame
	if err := json.Unmarshal(received, &frame); err != nil || string(frame.Payload) != "still-connected" {
		t.Fatalf("frame=%+v err=%v", frame, err)
	}
}

func TestHubRegistrationAndInvalidFrames(t *testing.T) {
	mate := newTestMate(t, "mate")
	hub := NewHub(mate.keys())
	mateP := &peer{mateID: "mate", role: "mate"}
	if err := hub.register(mateP); err != nil {
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
	hub.unregister(mateP)

	server := httptest.NewServer(NewHub(mate.keys()))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn := dialPeer(t, ctx, server.URL, mate, "mate", "device", "device")
	if err := conn.Write(ctx, websocket.MessageText, []byte("text")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := conn.Read(ctx); err == nil {
		t.Fatal("text frame did not close connection")
	}
	conn.CloseNow()

	conn = dialPeer(t, ctx, server.URL, mate, "mate", "device", "device")
	if err := conn.Write(ctx, websocket.MessageBinary, []byte("not-json")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := conn.Read(ctx); err == nil {
		t.Fatal("invalid frame did not close connection")
	}
	conn.CloseNow()
}

// dialPeer dials /v1/connect, minting a token with the scope the role
// requires. mate's registered mate_id is used for the token's mate_id --
// pass the dial's own mateID separately only when a test deliberately
// wants to exercise a mismatch (callers here always pass mate.id).
func dialPeer(t *testing.T, ctx context.Context, serverURL string, mate testMate, mateID, role, deviceID string) *websocket.Conn {
	t.Helper()
	url := "ws" + strings.TrimPrefix(serverURL, "http") + "/v1/connect?mate_id=" + mateID + "&role=" + role
	if deviceID != "" {
		url += "&device_id=" + deviceID
	}
	scope := security.RelayScopeDevice
	if role == "mate" {
		scope = security.RelayScopeMate
	}
	header := make(http.Header)
	header.Set("Authorization", "Bearer "+mate.mint(t, scope, deviceID, time.Minute))
	conn, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{HTTPHeader: header})
	if err != nil {
		t.Fatal(err)
	}
	// Mirror the production dialers (hub.go's Accept, connector.go's Dial):
	// raise coder/websocket's 32768-byte default so tests can exercise
	// frames up to MaxFrameBytes without the client side choking first.
	conn.SetReadLimit(MaxFrameBytes)
	return conn
}
