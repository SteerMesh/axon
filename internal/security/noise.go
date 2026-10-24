package security

import (
	"crypto/subtle"
	"fmt"

	"github.com/flynn/noise"
)

var cipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)

type IKInitiator struct{ state *noise.HandshakeState }
type IKResponder struct{ state *noise.HandshakeState }

type Channel struct {
	Send *noise.CipherState
	Recv *noise.CipherState
}

func NewIKInitiator(local noise.DHKey, peerStatic, prologue []byte) (*IKInitiator, error) {
	if len(local.Private) != 32 || len(local.Public) != 32 || len(peerStatic) != 32 {
		return nil, fmt.Errorf("Noise IK requires 32-byte local and peer static keys")
	}
	state, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: cipherSuite, Pattern: noise.HandshakeIK, Initiator: true,
		StaticKeypair: local, PeerStatic: append([]byte(nil), peerStatic...), Prologue: append([]byte(nil), prologue...),
	})
	if err != nil {
		return nil, err
	}
	return &IKInitiator{state: state}, nil
}

func NewIKResponder(local noise.DHKey, prologue []byte) (*IKResponder, error) {
	if len(local.Private) != 32 || len(local.Public) != 32 {
		return nil, fmt.Errorf("Noise IK requires a 32-byte local static keypair")
	}
	state, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: cipherSuite, Pattern: noise.HandshakeIK, Initiator: false,
		StaticKeypair: local, Prologue: append([]byte(nil), prologue...),
	})
	if err != nil {
		return nil, err
	}
	return &IKResponder{state: state}, nil
}

func (i *IKInitiator) Start(payload []byte) ([]byte, error) {
	message, send, recv, err := i.state.WriteMessage(nil, payload)
	if err != nil {
		return nil, err
	}
	if send != nil || recv != nil {
		return nil, fmt.Errorf("Noise IK completed before responder message")
	}
	return message, nil
}

func (r *IKResponder) Accept(message, expectedPeerStatic []byte) ([]byte, error) {
	payload, send, recv, err := r.state.ReadMessage(nil, message)
	if err != nil {
		return nil, err
	}
	if send != nil || recv != nil {
		return nil, fmt.Errorf("Noise IK completed before responder reply")
	}
	actual := r.state.PeerStatic()
	if len(expectedPeerStatic) != len(actual) || subtle.ConstantTimeCompare(actual, expectedPeerStatic) != 1 {
		return nil, fmt.Errorf("Noise initiator is not the paired device")
	}
	return payload, nil
}

func (r *IKResponder) Reply(payload []byte) ([]byte, Channel, error) {
	message, initiatorToResponder, responderToInitiator, err := r.state.WriteMessage(nil, payload)
	if err != nil {
		return nil, Channel{}, err
	}
	if initiatorToResponder == nil || responderToInitiator == nil {
		return nil, Channel{}, fmt.Errorf("Noise IK did not complete")
	}
	return message, Channel{Send: responderToInitiator, Recv: initiatorToResponder}, nil
}

func (i *IKInitiator) Finish(message []byte) ([]byte, Channel, error) {
	payload, initiatorToResponder, responderToInitiator, err := i.state.ReadMessage(nil, message)
	if err != nil {
		return nil, Channel{}, err
	}
	if initiatorToResponder == nil || responderToInitiator == nil {
		return nil, Channel{}, fmt.Errorf("Noise IK did not complete")
	}
	return payload, Channel{Send: initiatorToResponder, Recv: responderToInitiator}, nil
}
