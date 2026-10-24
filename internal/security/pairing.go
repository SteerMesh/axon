package security

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

const pairingDomain = "mesh-axon-pairing-v1"

type PairingBundle struct {
	MateID         string    `json:"mate_id"`
	MateSigningKey []byte    `json:"mate_signing_key"`
	MateNoiseKey   []byte    `json:"mate_noise_key"`
	RelayURL       string    `json:"relay_url"`
	OneTimeToken   string    `json:"one_time_token"`
	ExpiresAt      time.Time `json:"expires_at"`
}

type DevicePresentation struct {
	DeviceID         string `json:"device_id"`
	DeviceSigningKey []byte `json:"device_signing_key"`
	DeviceNoiseKey   []byte `json:"device_noise_key"`
	Signature        []byte `json:"signature"`
}

type DeviceRecord struct {
	MateID           string    `json:"mate_id"`
	DeviceID         string    `json:"device_id"`
	DeviceSigningKey []byte    `json:"device_signing_key"`
	DeviceNoiseKey   []byte    `json:"device_noise_key"`
	PairedAt         time.Time `json:"paired_at"`
	MateSignature    []byte    `json:"mate_signature"`
}

type PairingManager struct {
	mu       sync.Mutex
	mateID   string
	relayURL string
	identity Identity
	tokens   map[[32]byte]time.Time
	now      func() time.Time
}

func NewPairingManager(mateID, relayURL string, identity Identity) *PairingManager {
	return &PairingManager{
		mateID: mateID, relayURL: relayURL, identity: identity,
		tokens: make(map[[32]byte]time.Time), now: time.Now,
	}
}

func (m *PairingManager) Issue(ttl time.Duration) (PairingBundle, error) {
	if ttl <= 0 {
		return PairingBundle{}, errors.New("pairing TTL must be positive")
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return PairingBundle{}, err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	expires := m.now().UTC().Add(ttl)
	m.mu.Lock()
	m.tokens[sha256.Sum256(raw)] = expires
	m.mu.Unlock()
	return PairingBundle{
		MateID: m.mateID, MateSigningKey: append([]byte(nil), m.identity.SigningPublic...),
		MateNoiseKey: append([]byte(nil), m.identity.Noise.Public...), RelayURL: m.relayURL,
		OneTimeToken: token, ExpiresAt: expires,
	}, nil
}

func SignPresentation(token, mateID string, identity Identity, deviceID string) (DevicePresentation, error) {
	presentation := DevicePresentation{
		DeviceID: deviceID, DeviceSigningKey: append([]byte(nil), identity.SigningPublic...),
		DeviceNoiseKey: append([]byte(nil), identity.Noise.Public...),
	}
	message, err := presentationMessage(token, mateID, presentation)
	if err != nil {
		return DevicePresentation{}, err
	}
	presentation.Signature = ed25519.Sign(identity.SigningPrivate, message)
	return presentation, nil
}

func (m *PairingManager) Complete(token string, presentation DevicePresentation) (DeviceRecord, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != 32 {
		return DeviceRecord{}, errors.New("invalid pairing token")
	}
	hash := sha256.Sum256(raw)
	m.mu.Lock()
	expires, exists := m.tokens[hash]
	m.mu.Unlock()
	if !exists || !m.now().Before(expires) {
		return DeviceRecord{}, errors.New("pairing token is invalid or expired")
	}
	if presentation.DeviceID == "" || len(presentation.DeviceSigningKey) != ed25519.PublicKeySize || len(presentation.DeviceNoiseKey) != 32 {
		return DeviceRecord{}, errors.New("invalid device identity")
	}
	message, err := presentationMessage(token, m.mateID, presentation)
	if err != nil {
		return DeviceRecord{}, err
	}
	if !ed25519.Verify(ed25519.PublicKey(presentation.DeviceSigningKey), message, presentation.Signature) {
		return DeviceRecord{}, errors.New("device identity signature is invalid")
	}
	// Consume only after identity verification. Re-check under the lock so two
	// concurrent valid presentations cannot both redeem the same token.
	m.mu.Lock()
	currentExpiry, exists := m.tokens[hash]
	if !exists || !currentExpiry.Equal(expires) || !m.now().Before(currentExpiry) {
		m.mu.Unlock()
		return DeviceRecord{}, errors.New("pairing token is invalid or expired")
	}
	delete(m.tokens, hash)
	m.mu.Unlock()
	record := DeviceRecord{
		MateID: m.mateID, DeviceID: presentation.DeviceID,
		DeviceSigningKey: append([]byte(nil), presentation.DeviceSigningKey...),
		DeviceNoiseKey:   append([]byte(nil), presentation.DeviceNoiseKey...),
		PairedAt:         m.now().UTC(),
	}
	binding, err := recordBinding(record)
	if err != nil {
		return DeviceRecord{}, err
	}
	record.MateSignature = ed25519.Sign(m.identity.SigningPrivate, binding)
	return record, nil
}

func VerifyDeviceRecord(record DeviceRecord, mateSigningKey ed25519.PublicKey) bool {
	binding, err := recordBinding(record)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeEq(int32(len(mateSigningKey)), ed25519.PublicKeySize) == 1 &&
		ed25519.Verify(mateSigningKey, binding, record.MateSignature)
}

func presentationMessage(token, mateID string, presentation DevicePresentation) ([]byte, error) {
	return json.Marshal(struct {
		Domain           string `json:"domain"`
		Token            string `json:"token"`
		MateID           string `json:"mate_id"`
		DeviceID         string `json:"device_id"`
		DeviceSigningKey []byte `json:"device_signing_key"`
		DeviceNoiseKey   []byte `json:"device_noise_key"`
	}{pairingDomain, token, mateID, presentation.DeviceID, presentation.DeviceSigningKey, presentation.DeviceNoiseKey})
}

func recordBinding(record DeviceRecord) ([]byte, error) {
	return json.Marshal(struct {
		Domain           string    `json:"domain"`
		MateID           string    `json:"mate_id"`
		DeviceID         string    `json:"device_id"`
		DeviceSigningKey []byte    `json:"device_signing_key"`
		DeviceNoiseKey   []byte    `json:"device_noise_key"`
		PairedAt         time.Time `json:"paired_at"`
	}{pairingDomain, record.MateID, record.DeviceID, record.DeviceSigningKey, record.DeviceNoiseKey, record.PairedAt})
}

func (b PairingBundle) QRPayload() (string, error) {
	data, err := json.Marshal(b)
	if err != nil {
		return "", fmt.Errorf("encode pairing bundle: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}
