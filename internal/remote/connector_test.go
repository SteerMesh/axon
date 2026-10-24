package remote

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SteerMesh/axon/internal/authz"
	"github.com/SteerMesh/axon/internal/domain"
	"github.com/SteerMesh/axon/internal/relay"
	"github.com/SteerMesh/axon/internal/security"
	"github.com/SteerMesh/axon/internal/session"
	"github.com/SteerMesh/axon/internal/store"
	"github.com/SteerMesh/axon/pkg/protocol"
	"github.com/coder/websocket"
)

func TestConnectorCarriesEncryptedCommandThroughRelay(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hub := relay.NewHub("relay-token")
	server := httptest.NewServer(hub)
	defer server.Close()
	persistent, err := store.Open(filepath.Join(t.TempDir(), "axon.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer persistent.Close()
	mate, _ := security.GenerateIdentity()
	device, _ := security.GenerateIdentity()
	record := security.DeviceRecord{
		MateID: "mate-1", DeviceID: "device-1", DeviceSigningKey: device.SigningPublic,
		DeviceNoiseKey: device.Noise.Public, PairedAt: time.Now(), MateSignature: []byte("test"),
	}
	if err := persistent.PutDevice(ctx, record, authz.RoleViewer); err != nil {
		t.Fatal(err)
	}
	r, w := io.Pipe()
	defer w.Close()
	manager := session.NewManager(1024, endpointAdapter{process: &endpointProcess{r: r}})
	managed, err := manager.Create(ctx, "push-test", domain.TargetSpec{Kind: "test"}, domain.PermissionInteractive)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := NewEndpoint("mate-1", mate, persistent, NewDispatcher(manager, persistent))
	connector := NewConnector(server.URL, "relay-token", "mate-1", endpoint)
	go func() { _ = connector.Run(ctx) }()
	deadline := time.Now().Add(3 * time.Second)
	for !hub.MateConnected("mate-1") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !hub.MateConnected("mate-1") {
		t.Fatal("Mate did not connect to relay")
	}

	deviceURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/v1/connect?mate_id=mate-1&role=device&device_id=device-1"
	header := make(http.Header)
	header.Set("Authorization", "Bearer relay-token")
	conn, _, err := websocket.Dial(ctx, deviceURL, &websocket.DialOptions{HTTPHeader: header, Subprotocols: []string{"axon.v1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	initiator, _ := security.NewIKInitiator(device.Noise, mate.Noise.Public, []byte("mesh-axon-v1:mate-1:device-1"))
	first, _ := initiator.Start([]byte("device-1"))
	handshakeReply := exchangeRoute(t, ctx, conn, append([]byte{packetHandshakeInit}, first...))
	_, channel, err := initiator.Finish(handshakeReply[1:])
	if err != nil {
		t.Fatal(err)
	}
	request := protocol.Envelope{Version: 1, ID: "request-1", Type: "sessions.list", Timestamp: time.Now()}
	encoded, _ := json.Marshal(request)
	encrypted, _ := channel.Send.Encrypt(nil, nil, encoded)
	reply := exchangeRoute(t, ctx, conn, append([]byte{packetTransport}, encrypted...))
	plaintext, err := channel.Recv.Decrypt(nil, nil, reply[1:])
	if err != nil {
		t.Fatal(err)
	}
	var response protocol.Envelope
	if err := json.Unmarshal(plaintext, &response); err != nil {
		t.Fatal(err)
	}
	if response.ReplyTo != request.ID {
		t.Fatalf("unexpected response: %+v", response)
	}

	subscribe := requestEnvelope("session.subscribe", managed.ID, "subscribe-1", map[string]any{"from_seq": 0})
	encoded, _ = json.Marshal(subscribe)
	encrypted, _ = channel.Send.Encrypt(nil, nil, encoded)
	reply = exchangeRoute(t, ctx, conn, append([]byte{packetTransport}, encrypted...))
	plaintext, err = channel.Recv.Decrypt(nil, nil, reply[1:])
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(plaintext, &response); err != nil {
		t.Fatal(err)
	}
	if response.ReplyTo != subscribe.ID || response.Epoch != managed.StreamEpoch {
		t.Fatalf("unexpected subscription response: %+v", response)
	}

	if _, err := w.Write([]byte("pushed-output")); err != nil {
		t.Fatal(err)
	}
	eventPacket := readRoute(t, ctx, conn)
	plaintext, err = channel.Recv.Decrypt(nil, nil, eventPacket[1:])
	if err != nil {
		t.Fatal(err)
	}
	var event protocol.Envelope
	if err := json.Unmarshal(plaintext, &event); err != nil {
		t.Fatal(err)
	}
	var output []byte
	if err := json.Unmarshal(event.Data, &output); err != nil {
		t.Fatal(err)
	}
	if event.Type != "session.output" || event.SessionID != managed.ID || event.Sequence != 1 || string(output) != "pushed-output" {
		t.Fatalf("unexpected pushed event: %+v output=%q", event, output)
	}
}

func TestConnectorValidationAndCancellation(t *testing.T) {
	connector := NewConnector("ftp://relay.example", "token", "mate", nil)
	if err := connector.runOnce(context.Background()); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("unsupported URL error=%v", err)
	}
	connector = NewConnector("%", "token", "mate", nil)
	if err := connector.runOnce(context.Background()); err == nil {
		t.Fatal("malformed URL accepted")
	}
	if err := connector.Send(context.Background(), "device", []byte("payload")); err == nil {
		t.Fatal("send succeeded without connection")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	connector = NewConnector("ftp://relay.example", "token", "mate", nil)
	if err := connector.Run(ctx); err != context.Canceled {
		t.Fatalf("canceled run error=%v", err)
	}

	ctx, cancel = context.WithCancel(context.Background())
	connector = NewConnector("ftp://relay.example", "token", "mate", nil)
	done := make(chan error, 1)
	go func() { done <- connector.Run(ctx) }()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatalf("run error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("connector did not stop during backoff")
	}
}

func exchangeRoute(t *testing.T, ctx context.Context, conn *websocket.Conn, payload []byte) []byte {
	t.Helper()
	frame, _ := json.Marshal(relay.RouteFrame{Version: 1, MateID: "mate-1", Payload: payload})
	if err := conn.Write(ctx, websocket.MessageBinary, frame); err != nil {
		t.Fatal(err)
	}
	return readRoute(t, ctx, conn)
}

func readRoute(t *testing.T, ctx context.Context, conn *websocket.Conn) []byte {
	t.Helper()
	_, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var response relay.RouteFrame
	if err := json.Unmarshal(data, &response); err != nil {
		t.Fatal(err)
	}
	return response.Payload
}
