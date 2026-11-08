package security

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// RelayTokenScope identifies what a Relay Access Token (RAT) authorizes.
type RelayTokenScope string

// Sentinel errors returned by VerifyRelayToken, exported so callers (the
// relay's metrics instrumentation in particular) can classify a failure by
// which check rejected it with errors.Is, instead of matching on error text.
var (
	// ErrRelayTokenInvalid covers everything about the token's own
	// encoding and cryptographic validity: malformed base64/JSON, a
	// signature that doesn't verify, or claims signed for a different
	// mate_id than the connection claims. All of these mean the same
	// thing to a caller -- the presented credential doesn't authenticate
	// as the identity this connection is for -- so they share one
	// sentinel rather than three.
	ErrRelayTokenInvalid = errors.New("relay token is malformed or does not verify")
	// ErrRelayTokenWrongScope means the token verified but its scope
	// isn't one of the scopes allowed on this connection.
	ErrRelayTokenWrongScope = errors.New("relay token scope is not permitted on this connection")
	// ErrRelayTokenDeviceMismatch means the token verified and its scope
	// is allowed, but it names a different device_id than the connection.
	ErrRelayTokenDeviceMismatch = errors.New("relay token device_id does not match connection")
	// ErrRelayTokenExpired means the token verified but its exp claim has
	// passed.
	ErrRelayTokenExpired = errors.New("relay token has expired")
)

const (
	// RelayScopeMate is minted by a mate for its own relay connection.
	RelayScopeMate RelayTokenScope = "mate"
	// RelayScopePairing is minted for the first, not-yet-authenticated
	// device connection during pairing. Its DeviceID is always empty
	// (wildcard) because the real device ID isn't known until the device
	// presents itself.
	RelayScopePairing RelayTokenScope = "pairing"
	// RelayScopeDevice is minted once a device has completed pairing and
	// its DeviceID is known.
	RelayScopeDevice RelayTokenScope = "device"
)

const (
	// MateRelayTokenTTL is how long a mate-scope RAT is valid. The mate
	// mints a fresh one before every dial attempt (minting is cheap and
	// the mate always holds its own key), so a short TTL costs nothing
	// and limits the blast radius if one ever leaks in transit.
	MateRelayTokenTTL = 5 * time.Minute
	// DeviceRelayTokenTTL is how long a device-scope RAT is valid. Unlike
	// the mate, a device cannot mint its own token -- it has no identity
	// key the relay recognizes -- so this needs to be long enough to
	// cover an ordinary session. relay.token.refresh (see dispatcher.go)
	// lets an already-connected device renew it before it expires.
	DeviceRelayTokenTTL = 24 * time.Hour
)

// RelayTokenClaims is the signed body of a Relay Access Token (RAT). A RAT
// is `base64url(json(claims)) + "." + base64url(signature)`, where
// signature is an Ed25519 signature by the mate's identity signing key
// (the same key used to sign DeviceRecords, see pairing.go) over the JSON
// bytes. There is no relay-side storage: the relay verifies a RAT purely
// by checking the signature against the claimed mate's registered public
// key and validating the claims below, never needing to know anything
// about the payload the token protects.
type RelayTokenClaims struct {
	MateID    string          `json:"mate_id"`
	Scope     RelayTokenScope `json:"scope"`
	DeviceID  string          `json:"device_id"`
	IssuedAt  int64           `json:"iat"`
	ExpiresAt int64           `json:"exp"`
}

// MintRelayToken signs a Relay Access Token with identity's signing key.
// Reusing the mate's existing identity key -- rather than provisioning a
// separate relay credential -- means a mate authorizes its own and its
// devices' relay traffic with exactly the key it already uses to vouch
// for paired devices.
func MintRelayToken(identity Identity, mateID string, scope RelayTokenScope, deviceID string, ttl time.Duration) (string, RelayTokenClaims, error) {
	if ttl <= 0 {
		return "", RelayTokenClaims{}, errors.New("relay token TTL must be positive")
	}
	if len(identity.SigningPrivate) != ed25519.PrivateKeySize {
		return "", RelayTokenClaims{}, errors.New("relay token minting requires a signing identity")
	}
	now := time.Now().UTC()
	claims := RelayTokenClaims{
		MateID:    mateID,
		Scope:     scope,
		DeviceID:  deviceID,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(ttl).Unix(),
	}
	token, err := encodeRelayToken(claims, identity.SigningPrivate)
	if err != nil {
		return "", RelayTokenClaims{}, err
	}
	return token, claims, nil
}

func encodeRelayToken(claims RelayTokenClaims, signingKey ed25519.PrivateKey) (string, error) {
	body, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("encode relay token claims: %w", err)
	}
	signature := ed25519.Sign(signingKey, body)
	return base64.RawURLEncoding.EncodeToString(body) + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

// VerifyRelayToken checks the token's signature against mateKey and then
// binds it to the connection it is being presented on: the claimed
// mate_id must equal wantMateID, the scope must be one allowedScopes
// permits for this kind of connection, the device_id must either be the
// wildcard (empty) or equal wantDeviceID exactly, and the token must not
// be expired as of now. The relay is the only caller of this function --
// it never decodes or trusts anything about the payload a RAT protects,
// which is what keeps the relay content-blind.
func VerifyRelayToken(token string, mateKey ed25519.PublicKey, wantMateID string, allowedScopes []RelayTokenScope, wantDeviceID string, now time.Time) (RelayTokenClaims, error) {
	claims, err := decodeRelayToken(token, mateKey)
	if err != nil {
		return RelayTokenClaims{}, err
	}
	if claims.MateID != wantMateID {
		return RelayTokenClaims{}, fmt.Errorf("relay token mate_id does not match connection: %w", ErrRelayTokenInvalid)
	}
	scopeAllowed := false
	for _, allowed := range allowedScopes {
		if claims.Scope == allowed {
			scopeAllowed = true
			break
		}
	}
	if !scopeAllowed {
		return RelayTokenClaims{}, fmt.Errorf("relay token scope %q is not permitted on this connection: %w", claims.Scope, ErrRelayTokenWrongScope)
	}
	if claims.DeviceID != "" && claims.DeviceID != wantDeviceID {
		return RelayTokenClaims{}, fmt.Errorf("relay token device_id does not match connection: %w", ErrRelayTokenDeviceMismatch)
	}
	if now.Unix() >= claims.ExpiresAt {
		return RelayTokenClaims{}, fmt.Errorf("relay token has expired: %w", ErrRelayTokenExpired)
	}
	return claims, nil
}

func decodeRelayToken(token string, mateKey ed25519.PublicKey) (RelayTokenClaims, error) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return RelayTokenClaims{}, fmt.Errorf("malformed relay token: %w", ErrRelayTokenInvalid)
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return RelayTokenClaims{}, fmt.Errorf("malformed relay token claims: %w", ErrRelayTokenInvalid)
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return RelayTokenClaims{}, fmt.Errorf("malformed relay token signature: %w", ErrRelayTokenInvalid)
	}
	if len(mateKey) != ed25519.PublicKeySize || !ed25519.Verify(mateKey, body, signature) {
		return RelayTokenClaims{}, fmt.Errorf("relay token signature is invalid: %w", ErrRelayTokenInvalid)
	}
	var claims RelayTokenClaims
	if err := json.Unmarshal(body, &claims); err != nil {
		return RelayTokenClaims{}, fmt.Errorf("malformed relay token claims: %w", ErrRelayTokenInvalid)
	}
	return claims, nil
}
