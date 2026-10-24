package remote

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/SteerMesh/axon/internal/authz"
	"github.com/SteerMesh/axon/internal/domain"
	"github.com/SteerMesh/axon/internal/security"
	"github.com/SteerMesh/axon/internal/session"
	"github.com/SteerMesh/axon/internal/store"
	"github.com/SteerMesh/axon/internal/target"
	"github.com/SteerMesh/axon/pkg/protocol"
)

type endpointAdapter struct{ process *endpointProcess }
type endpointProcess struct{ r *io.PipeReader }

func (a endpointAdapter) Kind() string { return "test" }
func (a endpointAdapter) Spawn(context.Context, domain.TargetSpec) (target.Process, error) {
	return a.process, nil
}
func (p *endpointProcess) Write(data []byte) (int, error) { return len(data), nil }
func (p *endpointProcess) Output() io.Reader              { return p.r }
func (p *endpointProcess) Resize(uint16, uint16) error    { return nil }
func (p *endpointProcess) Signal(target.Signal) error     { return nil }
func (p *endpointProcess) Wait() (int, error)             { select {} }
func (p *endpointProcess) Close() error                   { return p.r.Close() }

func TestEndpointAuthenticatesAndDispatchesEncryptedRequest(t *testing.T) {
	ctx := context.Background()
	mate, _ := security.GenerateIdentity()
	deviceIdentity, _ := security.GenerateIdentity()
	persistent, err := store.Open(filepath.Join(t.TempDir(), "axon.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer persistent.Close()
	r, _ := io.Pipe()
	manager := session.NewManager(1024, endpointAdapter{process: &endpointProcess{r: r}})
	dispatcher := NewDispatcher(manager, persistent)
	pairing := security.NewPairingManager("mate-1", "wss://relay.example", mate)
	endpoint := NewEndpoint("mate-1", mate, persistent, dispatcher).WithPairing(pairing)
	bundle, err := pairing.Issue(5 * time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	presentation, err := security.SignPresentation(bundle.OneTimeToken, bundle.MateID, deviceIdentity, "device-1")
	if err != nil {
		t.Fatal(err)
	}
	pairRequest, _ := json.Marshal(map[string]any{"token": bundle.OneTimeToken, "presentation": presentation})
	pairReply, err := endpoint.Process(ctx, "device-1", append([]byte{packetPairingInit}, pairRequest...))
	if err != nil || pairReply[0] != packetPairingReply {
		t.Fatalf("pairing failed: %v", err)
	}

	prologue := []byte("mesh-axon-v1:mate-1:device-1")
	initiator, _ := security.NewIKInitiator(deviceIdentity.Noise, mate.Noise.Public, prologue)
	first, _ := initiator.Start([]byte("device-1"))
	reply, err := endpoint.Process(ctx, "device-1", append([]byte{packetHandshakeInit}, first...))
	if err != nil {
		t.Fatal(err)
	}
	_, channel, err := initiator.Finish(reply[1:])
	if err != nil {
		t.Fatal(err)
	}

	request := protocol.Envelope{Version: 1, ID: "request-1", Type: "sessions.list", Timestamp: time.Now()}
	encoded, _ := json.Marshal(request)
	encrypted, _ := channel.Send.Encrypt(nil, nil, encoded)
	responsePacket, err := endpoint.Process(ctx, "device-1", append([]byte{packetTransport}, encrypted...))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := channel.Recv.Decrypt(nil, nil, responsePacket[1:])
	if err != nil {
		t.Fatal(err)
	}
	var response protocol.Envelope
	if err := json.Unmarshal(plaintext, &response); err != nil {
		t.Fatal(err)
	}
	if response.ReplyTo != request.ID || response.Type != "sessions.list.response" {
		t.Fatalf("unexpected response: %+v", response)
	}
}

func TestEndpointRepairingDeviceReplacesEstablishedChannel(t *testing.T) {
	ctx := context.Background()
	endpoint, persistent, deviceID, _ := pairedEndpoint(t)
	defer persistent.Close()

	device, err := security.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	pairing := security.NewPairingManager("mate-1", "wss://relay.example", endpoint.identity)
	endpoint.WithPairing(pairing)
	bundle, err := pairing.Issue(5 * time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	presentation, err := security.SignPresentation(bundle.OneTimeToken, bundle.MateID, device, deviceID)
	if err != nil {
		t.Fatal(err)
	}
	pairRequest, _ := json.Marshal(map[string]any{"token": bundle.OneTimeToken, "presentation": presentation})
	if _, err := endpoint.Process(ctx, deviceID, append([]byte{packetPairingInit}, pairRequest...)); err != nil {
		t.Fatal(err)
	}

	initiator, err := security.NewIKInitiator(device.Noise, endpoint.identity.Noise.Public, []byte("mesh-axon-v1:mate-1:"+deviceID))
	if err != nil {
		t.Fatal(err)
	}
	first, err := initiator.Start([]byte(deviceID))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := endpoint.Process(ctx, deviceID, append([]byte{packetHandshakeInit}, first...)); err != nil {
		t.Fatalf("replacement handshake failed: %v", err)
	}
}

func TestEndpointRejectsInvalidProtocolStates(t *testing.T) {
	ctx := context.Background()
	mate, _ := security.GenerateIdentity()
	persistent, err := store.Open(filepath.Join(t.TempDir(), "axon.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer persistent.Close()
	manager := session.NewManager(1024)
	endpoint := NewEndpoint("mate-1", mate, persistent, NewDispatcher(manager, persistent))
	if _, err := endpoint.Process(ctx, "device", []byte{packetTransport}); err == nil {
		t.Fatal("short packet accepted")
	}
	payload, _ := json.Marshal(map[string]any{})
	if _, err := endpoint.Process(ctx, "device", append([]byte{packetPairingInit}, payload...)); err == nil {
		t.Fatal("pairing succeeded while disabled")
	}
	pairing := security.NewPairingManager("mate-1", "relay", mate)
	endpoint.WithPairing(pairing)
	if _, err := endpoint.Process(ctx, "device", []byte{packetPairingInit, '{'}); err == nil {
		t.Fatal("invalid pairing JSON accepted")
	}
	invalidPairing, _ := json.Marshal(map[string]any{"token": "invalid", "presentation": security.DevicePresentation{}})
	if _, err := endpoint.Process(ctx, "device", append([]byte{packetPairingInit}, invalidPairing...)); err == nil {
		t.Fatal("invalid pairing token accepted")
	}
	if _, err := endpoint.Process(ctx, "device", []byte{packetTransport, 1}); err == nil {
		t.Fatal("transport accepted before handshake")
	}
	if _, err := endpoint.Process(ctx, "missing", []byte{packetHandshakeInit, 1}); err == nil {
		t.Fatal("unknown device handshake succeeded")
	}

	device, _ := security.GenerateIdentity()
	record := security.DeviceRecord{MateID: "mate-1", DeviceID: "revoked", DeviceSigningKey: device.SigningPublic, DeviceNoiseKey: device.Noise.Public, PairedAt: time.Now(), MateSignature: []byte("test")}
	if err := persistent.PutDevice(ctx, record, authz.RoleOwner); err != nil {
		t.Fatal(err)
	}
	if err := persistent.RevokeDevice(ctx, record.DeviceID, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := endpoint.Process(ctx, record.DeviceID, []byte{packetHandshakeInit, 1}); err == nil {
		t.Fatal("revoked device handshake succeeded")
	}
}

func TestEndpointDropsInvalidAndRevokedEstablishedChannels(t *testing.T) {
	ctx := context.Background()
	endpoint, persistent, device, channel := pairedEndpoint(t)
	defer persistent.Close()
	if _, err := endpoint.Process(ctx, "device-1", []byte{packetHandshakeInit, 1}); err == nil {
		t.Fatal("unexpected packet type accepted")
	}
	if _, err := endpoint.Process(ctx, "device-1", []byte{packetTransport, 1, 2, 3}); err == nil {
		t.Fatal("invalid ciphertext accepted")
	}
	if _, err := endpoint.Process(ctx, "device-1", []byte{packetTransport, 1}); err == nil || !strings.Contains(err.Error(), "handshake") {
		t.Fatalf("channel was not dropped: %v", err)
	}

	endpoint, persistent, device, channel = pairedEndpoint(t)
	defer persistent.Close()
	badJSON, _ := channel.Send.Encrypt(nil, nil, []byte("not-json"))
	if _, err := endpoint.Process(ctx, device, append([]byte{packetTransport}, badJSON...)); err == nil {
		t.Fatal("invalid plaintext accepted")
	}

	endpoint, persistent, device, channel = pairedEndpoint(t)
	defer persistent.Close()
	if err := persistent.RevokeDevice(ctx, device, time.Now()); err != nil {
		t.Fatal(err)
	}
	request, _ := json.Marshal(protocol.Envelope{Version: 1, ID: "request", Type: "sessions.list", Timestamp: time.Now()})
	ciphertext, _ := channel.Send.Encrypt(nil, nil, request)
	if _, err := endpoint.Process(ctx, device, append([]byte{packetTransport}, ciphertext...)); err == nil || !strings.Contains(err.Error(), "not active") {
		t.Fatalf("revoked established channel accepted: %v", err)
	}
	endpoint.Revoke(device)
}

func TestEndpointPushesOutputAndClosureAndReplacesSubscription(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	endpoint := &Endpoint{subs: make(map[string]*activeSubscription)}
	events := make(chan protocol.Envelope, 4)
	emit := func(event protocol.Envelope) error {
		events <- event
		return nil
	}

	firstCanceled := make(chan struct{})
	var firstCancelOnce sync.Once
	firstChunks := make(chan session.Chunk)
	endpoint.Activate(ctx, "device", &Subscription{
		SessionID: "first", Epoch: "epoch-1", Chunks: firstChunks,
		Cancel: func() { firstCancelOnce.Do(func() { close(firstCanceled) }) },
	}, emit)

	secondCanceled := make(chan struct{})
	var secondCancelOnce sync.Once
	secondChunks := make(chan session.Chunk, 1)
	endpoint.Activate(ctx, "device", &Subscription{
		SessionID: "second", Epoch: "epoch-2", Chunks: secondChunks,
		Cancel: func() { secondCancelOnce.Do(func() { close(secondCanceled) }) },
	}, emit)
	select {
	case <-firstCanceled:
	case <-time.After(time.Second):
		t.Fatal("replaced subscription was not canceled")
	}

	secondChunks <- session.Chunk{Sequence: 7, Data: []byte("live")}
	close(secondChunks)
	output := <-events
	closed := <-events
	var data []byte
	if err := json.Unmarshal(output.Data, &data); err != nil {
		t.Fatal(err)
	}
	if output.Type != "session.output" || output.SessionID != "second" || output.Epoch != "epoch-2" || output.Sequence != 7 || string(data) != "live" {
		t.Fatalf("unexpected output event: %+v data=%q", output, data)
	}
	if closed.Type != "session.closed" || closed.SessionID != "second" || closed.Epoch != "epoch-2" {
		t.Fatalf("unexpected closed event: %+v", closed)
	}
	select {
	case <-secondCanceled:
	case <-time.After(time.Second):
		t.Fatal("completed subscription was not canceled")
	}
}

func TestEndpointRequestsResyncWhenRunningSubscriptionFallsBehind(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	endpoint := &Endpoint{subs: make(map[string]*activeSubscription)}
	events := make(chan protocol.Envelope, 1)
	chunks := make(chan session.Chunk)
	close(chunks)

	endpoint.Activate(ctx, "device", &Subscription{
		SessionID: "running", Epoch: "epoch-1", Chunks: chunks,
		State:  func() domain.SessionState { return domain.StateRunning },
		Cancel: func() {},
	}, func(event protocol.Envelope) error {
		events <- event
		return nil
	})

	select {
	case event := <-events:
		if event.Type != "session.resync" || event.SessionID != "running" || event.Epoch != "epoch-1" {
			t.Fatalf("unexpected resync event: %+v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("resync event was not emitted")
	}
}

func TestEndpointSubscriptionCleanupPaths(t *testing.T) {
	endpoint := &Endpoint{
		channels: make(map[string]security.Channel),
		subs:     make(map[string]*activeSubscription),
	}
	if _, err := endpoint.Encrypt("missing", protocol.Envelope{}); err == nil {
		t.Fatal("encryption succeeded without an established channel")
	}
	endpoint.Revoke("missing")

	ctx := context.Background()
	canceled := make(chan struct{})
	var cancelOnce sync.Once
	endpoint.Activate(ctx, "device", &Subscription{
		SessionID: "session", Chunks: make(chan session.Chunk),
		Cancel: func() { cancelOnce.Do(func() { close(canceled) }) },
	}, func(protocol.Envelope) error { return nil })
	endpoint.Activate(ctx, "device", nil, func(protocol.Envelope) error { return nil })
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("subscription was not canceled when cleared")
	}

	emitCanceled := make(chan struct{})
	chunks := make(chan session.Chunk, 1)
	chunks <- session.Chunk{Sequence: 1, Data: []byte("output")}
	endpoint.Activate(ctx, "device", &Subscription{
		SessionID: "session", Chunks: chunks,
		Cancel: func() { close(emitCanceled) },
	}, func(protocol.Envelope) error { return errors.New("send failed") })
	select {
	case <-emitCanceled:
	case <-time.After(time.Second):
		t.Fatal("subscription was not canceled after an emit failure")
	}
}

func pairedEndpoint(t *testing.T) (*Endpoint, *store.Store, string, security.Channel) {
	t.Helper()
	ctx := context.Background()
	mate, _ := security.GenerateIdentity()
	device, _ := security.GenerateIdentity()
	persistent, err := store.Open(filepath.Join(t.TempDir(), "axon.db"))
	if err != nil {
		t.Fatal(err)
	}
	record := security.DeviceRecord{MateID: "mate-1", DeviceID: "device-1", DeviceSigningKey: device.SigningPublic, DeviceNoiseKey: device.Noise.Public, PairedAt: time.Now(), MateSignature: []byte("test")}
	if err := persistent.PutDevice(ctx, record, authz.RoleOwner); err != nil {
		t.Fatal(err)
	}
	endpoint := NewEndpoint("mate-1", mate, persistent, NewDispatcher(session.NewManager(1024), persistent))
	initiator, _ := security.NewIKInitiator(device.Noise, mate.Noise.Public, []byte("mesh-axon-v1:mate-1:device-1"))
	first, _ := initiator.Start([]byte("device-1"))
	reply, err := endpoint.Process(ctx, "device-1", append([]byte{packetHandshakeInit}, first...))
	if err != nil {
		t.Fatal(err)
	}
	_, channel, err := initiator.Finish(reply[1:])
	if err != nil {
		t.Fatal(err)
	}
	return endpoint, persistent, "device-1", channel
}
