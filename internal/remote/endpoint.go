package remote

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/SteerMesh/axon/internal/authz"
	"github.com/SteerMesh/axon/internal/domain"
	"github.com/SteerMesh/axon/internal/security"
	"github.com/SteerMesh/axon/internal/store"
	"github.com/SteerMesh/axon/pkg/protocol"
	"github.com/oklog/ulid/v2"
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
	subs       map[string]*activeSubscription
	pairing    *security.PairingManager
}

type Outbound struct {
	Packet       []byte
	Envelope     *protocol.Envelope
	Subscription *Subscription
}

type activeSubscription struct {
	cancel context.CancelFunc
}

func (e *Endpoint) WithPairing(pairing *security.PairingManager) *Endpoint {
	e.pairing = pairing
	return e
}

func NewEndpoint(mateID string, identity security.Identity, persistent *store.Store, dispatcher *Dispatcher) *Endpoint {
	return &Endpoint{
		mateID: mateID, identity: identity, store: persistent, dispatcher: dispatcher,
		channels: make(map[string]security.Channel), subs: make(map[string]*activeSubscription),
	}
}

func (e *Endpoint) Process(ctx context.Context, deviceID string, packet []byte) ([]byte, error) {
	outbound, err := e.Handle(ctx, deviceID, packet)
	if err != nil {
		return nil, err
	}
	if outbound.Envelope != nil {
		// Process is the synchronous compatibility path and cannot forward a
		// live capability. Avoid retaining a subscriber when it receives a
		// subscription request.
		if outbound.Subscription != nil && outbound.Subscription.Cancel != nil {
			outbound.Subscription.Cancel()
		}
		return e.Encrypt(deviceID, *outbound.Envelope)
	}
	return outbound.Packet, nil
}

// Handle authenticates and decrypts one inbound packet. Transport responses
// remain plaintext envelopes so Connector can serialize Noise encryption and
// WebSocket writes in exactly the same order as pushed events.
func (e *Endpoint) Handle(ctx context.Context, deviceID string, packet []byte) (Outbound, error) {
	if len(packet) < 2 {
		return Outbound{}, errors.New("encrypted packet is too short")
	}
	if packet[0] == packetPairingInit {
		reply, err := e.completePairing(ctx, packet[1:])
		return Outbound{Packet: reply}, err
	}
	e.mu.Lock()
	channel, established := e.channels[deviceID]
	e.mu.Unlock()

	if !established {
		if packet[0] != packetHandshakeInit {
			return Outbound{}, errors.New("device must complete Noise handshake")
		}
		device, err := e.store.Device(ctx, deviceID)
		if err != nil {
			return Outbound{}, fmt.Errorf("load paired device: %w", err)
		}
		if device.RevokedAt != nil {
			return Outbound{}, errors.New("device is revoked")
		}
		prologue := []byte("mesh-axon-v1:" + e.mateID + ":" + deviceID)
		responder, err := security.NewIKResponder(e.identity.Noise, prologue)
		if err != nil {
			return Outbound{}, err
		}
		if _, err := responder.Accept(packet[1:], device.Record.DeviceNoiseKey); err != nil {
			return Outbound{}, err
		}
		reply, establishedChannel, err := responder.Reply([]byte(e.mateID))
		if err != nil {
			return Outbound{}, err
		}
		e.mu.Lock()
		e.channels[deviceID] = establishedChannel
		e.mu.Unlock()
		return Outbound{Packet: append([]byte{packetHandshakeReply}, reply...)}, nil
	}

	if packet[0] != packetTransport {
		return Outbound{}, errors.New("unexpected packet type on established channel")
	}
	plaintext, err := channel.Recv.Decrypt(nil, nil, packet[1:])
	if err != nil {
		e.drop(deviceID)
		return Outbound{}, fmt.Errorf("decrypt device packet: %w", err)
	}
	var request protocol.Envelope
	if err := json.Unmarshal(plaintext, &request); err != nil {
		return Outbound{}, err
	}
	device, err := e.store.Device(ctx, deviceID)
	if err != nil || device.RevokedAt != nil {
		e.drop(deviceID)
		return Outbound{}, errors.New("device is not active")
	}
	deviceContext := DeviceContext{ID: deviceID, Role: device.Role}
	if request.Type == "session.subscribe" {
		response, subscription := e.dispatcher.Subscribe(ctx, deviceContext, request)
		return Outbound{Envelope: &response, Subscription: subscription}, nil
	}
	response := e.dispatcher.Handle(ctx, deviceContext, request)
	return Outbound{Envelope: &response}, nil
}

// Encrypt serializes an application envelope for an established device. The
// caller must serialize calls with the corresponding transport write so Noise
// nonces and WebSocket frame order cannot diverge.
func (e *Endpoint) Encrypt(deviceID string, envelope protocol.Envelope) ([]byte, error) {
	e.mu.Lock()
	channel, established := e.channels[deviceID]
	e.mu.Unlock()
	if !established {
		return nil, errors.New("device Noise channel is not established")
	}
	encoded, err := json.Marshal(envelope)
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

// Activate starts forwarding a subscription after its response has been sent.
// A device has at most one active remote terminal subscription.
func (e *Endpoint) Activate(ctx context.Context, deviceID string, subscription *Subscription, emit func(protocol.Envelope) error) {
	e.mu.Lock()
	if previous := e.subs[deviceID]; previous != nil {
		previous.cancel()
	}
	if subscription == nil || subscription.Chunks == nil || subscription.Cancel == nil {
		delete(e.subs, deviceID)
		e.mu.Unlock()
		return
	}
	subscriptionCtx, cancelContext := context.WithCancel(ctx)
	active := &activeSubscription{}
	active.cancel = func() {
		cancelContext()
		subscription.Cancel()
	}
	e.subs[deviceID] = active
	e.mu.Unlock()

	go func() {
		defer func() {
			e.mu.Lock()
			if e.subs[deviceID] == active {
				delete(e.subs, deviceID)
			}
			e.mu.Unlock()
			subscription.Cancel()
		}()
		for {
			select {
			case <-subscriptionCtx.Done():
				return
			case chunk, ok := <-subscription.Chunks:
				if !ok {
					if subscriptionCtx.Err() != nil || !e.isActiveSubscription(deviceID, active) {
						return
					}
					eventType := "session.closed"
					if subscription.State != nil {
						switch subscription.State() {
						case domain.StateRunning, domain.StateIdle, domain.StateWaitingForInput:
							eventType = "session.resync"
						}
					}
					_ = emit(protocol.Envelope{
						Version: protocol.Version, ID: newEnvelopeID(), Type: eventType,
						SessionID: subscription.SessionID, Epoch: subscription.Epoch, Timestamp: time.Now().UTC(),
					})
					return
				}
				data, err := json.Marshal(chunk.Data)
				if err != nil {
					return
				}
				if err := emit(protocol.Envelope{
					Version: protocol.Version, ID: newEnvelopeID(), Type: "session.output",
					SessionID: subscription.SessionID, Epoch: subscription.Epoch,
					Sequence: chunk.Sequence, Timestamp: time.Now().UTC(), Data: data,
				}); err != nil {
					return
				}
			}
		}
	}()
}

func (e *Endpoint) isActiveSubscription(deviceID string, subscription *activeSubscription) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.subs[deviceID] == subscription
}

func newEnvelopeID() string {
	return ulid.Make().String()
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
	if subscription := e.subs[deviceID]; subscription != nil {
		subscription.cancel()
		delete(e.subs, deviceID)
	}
	delete(e.channels, deviceID)
	e.mu.Unlock()
}
