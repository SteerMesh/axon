package remote

import (
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
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
