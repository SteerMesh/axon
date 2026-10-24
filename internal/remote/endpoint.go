package remote

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/SteerMesh/axon/internal/authz"
	"github.com/SteerMesh/axon/internal/security"
	"github.com/SteerMesh/axon/internal/store"
	"github.com/SteerMesh/axon/pkg/protocol"
)

const (
	packetPairingInit    byte = 0
	packetHandshakeInit  byte = 1
	packetHandshakeReply byte = 2
	packetTransport      byte = 3
	packetPairingReply   byte = 4
)

type Endpoint struct {
	mateID     string
	identity   security.Identity
	store      *store.Store
	dispatcher *Dispatcher
	mu         sync.Mutex
	channels   map[string]security.Channel
	pairing    *security.PairingManager
}

func (e *Endpoint) WithPairing(pairing *security.PairingManager) *Endpoint {
	e.pairing = pairing
	return e
}

func NewEndpoint(mateID string, identity security.Identity, persistent *store.Store, dispatcher *Dispatcher) *Endpoint {
	return &Endpoint{mateID: mateID, identity: identity, store: persistent, dispatcher: dispatcher, channels: make(map[string]security.Channel)}
}

func (e *Endpoint) Process(ctx context.Context, deviceID string, packet []byte) ([]byte, error) {
	if len(packet) < 2 {
		return nil, errors.New("encrypted packet is too short")
	}
	if packet[0] == packetPairingInit {
		return e.completePairing(ctx, packet[1:])
	}
	e.mu.Lock()
	channel, established := e.channels[deviceID]
	e.mu.Unlock()

	if !established {
		if packet[0] != packetHandshakeInit {
			return nil, errors.New("device must complete Noise handshake")
		}
		device, err := e.store.Device(ctx, deviceID)
		if err != nil {
			return nil, fmt.Errorf("load paired device: %w", err)
		}
		if device.RevokedAt != nil {
			return nil, errors.New("device is revoked")
		}
		prologue := []byte("mesh-axon-v1:" + e.mateID + ":" + deviceID)
		responder, err := security.NewIKResponder(e.identity.Noise, prologue)
		if err != nil {
			return nil, err
		}
		if _, err := responder.Accept(packet[1:], device.Record.DeviceNoiseKey); err != nil {
			return nil, err
		}
		reply, establishedChannel, err := responder.Reply([]byte(e.mateID))
		if err != nil {
			return nil, err
		}
		e.mu.Lock()
		e.channels[deviceID] = establishedChannel
		e.mu.Unlock()
		return append([]byte{packetHandshakeReply}, reply...), nil
	}

	if packet[0] != packetTransport {
		return nil, errors.New("unexpected packet type on established channel")
	}
	plaintext, err := channel.Recv.Decrypt(nil, nil, packet[1:])
	if err != nil {
		e.drop(deviceID)
		return nil, fmt.Errorf("decrypt device packet: %w", err)
	}
	var request protocol.Envelope
	if err := json.Unmarshal(plaintext, &request); err != nil {
		return nil, err
	}
	device, err := e.store.Device(ctx, deviceID)
	if err != nil || device.RevokedAt != nil {
		e.drop(deviceID)
		return nil, errors.New("device is not active")
	}
	response := e.dispatcher.Handle(ctx, DeviceContext{ID: deviceID, Role: device.Role}, request)
	encoded, err := json.Marshal(response)
	if err != nil {
		return nil, err
	}
	encrypted, err := channel.Send.Encrypt(nil, nil, encoded)
	if err != nil {
		e.drop(deviceID)
		return nil, err
	}
	return append([]byte{packetTransport}, encrypted...), nil
}

func (e *Endpoint) completePairing(ctx context.Context, payload []byte) ([]byte, error) {
	if e.pairing == nil {
		return nil, errors.New("pairing is not enabled")
	}
	var request struct {
		Token        string                      `json:"token"`
		Presentation security.DevicePresentation `json:"presentation"`
	}
	if err := json.Unmarshal(payload, &request); err != nil {
		return nil, err
	}
	record, err := e.pairing.Complete(request.Token, request.Presentation)
	if err != nil {
		return nil, err
	}
	if err := e.store.PutDevice(ctx, record, authz.RoleOwner); err != nil {
		return nil, err
	}
	// A browser may pair the same device again after a reload or interrupted
	// transport. Its new Noise handshake must replace the old channel state.
	e.drop(record.DeviceID)
	encoded, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	return append([]byte{packetPairingReply}, encoded...), nil
}

func (e *Endpoint) Revoke(deviceID string) { e.drop(deviceID) }

func (e *Endpoint) drop(deviceID string) {
	e.mu.Lock()
	delete(e.channels, deviceID)
	e.mu.Unlock()
}
