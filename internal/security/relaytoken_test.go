package security

import (
	"strings"
	"testing"
	"time"
)

func TestMintRelayTokenValidatesInput(t *testing.T) {
	identity, _ := GenerateIdentity()
	if _, _, err := MintRelayToken(identity, "mate-1", RelayScopeMate, "", 0); err == nil {
		t.Fatal("non-positive TTL accepted")
	}
	if _, _, err := MintRelayToken(Identity{}, "mate-1", RelayScopeMate, "", time.Minute); err == nil {
		t.Fatal("missing signing identity accepted")
	}
}

func TestRelayTokenRoundTrips(t *testing.T) {
	identity, _ := GenerateIdentity()
	token, claims, err := MintRelayToken(identity, "mate-1", RelayScopeMate, "", MateRelayTokenTTL)
	if err != nil {
		t.Fatal(err)
	}
	if claims.MateID != "mate-1" || claims.Scope != RelayScopeMate || claims.DeviceID != "" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
	if claims.ExpiresAt <= claims.IssuedAt {
		t.Fatalf("expiry did not advance: %+v", claims)
	}
	got, err := VerifyRelayToken(token, identity.SigningPublic, "mate-1", []RelayTokenScope{RelayScopeMate}, "", time.Now())
	if err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	if got != claims {
		t.Fatalf("decoded claims = %+v, want %+v", got, claims)
	}
}

func TestVerifyRelayTokenRejectsTamperedClaims(t *testing.T) {
	identity, _ := GenerateIdentity()
	token, _, err := MintRelayToken(identity, "mate-1", RelayScopeMate, "", MateRelayTokenTTL)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		t.Fatalf("unexpected token shape: %q", token)
	}
	// Flip a character in the claims segment; the signature was computed
	// over the original bytes, so this must fail verification rather than
	// silently decoding to different claims.
	tamperedClaims := flipRune(parts[0])
	tampered := tamperedClaims + "." + parts[1]
	if _, err := VerifyRelayToken(tampered, identity.SigningPublic, "mate-1", []RelayTokenScope{RelayScopeMate}, "", time.Now()); err == nil {
		t.Fatal("tampered claims accepted")
	}
}

func TestVerifyRelayTokenRejectsTamperedSignature(t *testing.T) {
	identity, _ := GenerateIdentity()
	token, _, err := MintRelayToken(identity, "mate-1", RelayScopeMate, "", MateRelayTokenTTL)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.SplitN(token, ".", 2)
	tampered := parts[0] + "." + flipRune(parts[1])
	if _, err := VerifyRelayToken(tampered, identity.SigningPublic, "mate-1", []RelayTokenScope{RelayScopeMate}, "", time.Now()); err == nil {
		t.Fatal("tampered signature accepted")
	}
}

func TestVerifyRelayTokenRejectsMalformedInput(t *testing.T) {
	identity, _ := GenerateIdentity()
	for _, token := range []string{"", "no-dot-here", "not-base64!!.also-not-base64!!"} {
		if _, err := VerifyRelayToken(token, identity.SigningPublic, "mate-1", []RelayTokenScope{RelayScopeMate}, "", time.Now()); err == nil {
			t.Fatalf("malformed token %q accepted", token)
		}
	}
	if _, err := VerifyRelayToken("x.y", nil, "mate-1", []RelayTokenScope{RelayScopeMate}, "", time.Now()); err == nil {
		t.Fatal("empty mate key accepted")
	}
}

func TestVerifyRelayTokenRejectsExpired(t *testing.T) {
	identity, _ := GenerateIdentity()
	token, claims, err := MintRelayToken(identity, "mate-1", RelayScopeMate, "", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	afterExpiry := time.Unix(claims.ExpiresAt, 0).Add(time.Second)
	if _, err := VerifyRelayToken(token, identity.SigningPublic, "mate-1", []RelayTokenScope{RelayScopeMate}, "", afterExpiry); err == nil {
		t.Fatal("expired token accepted")
	}
}

func TestVerifyRelayTokenRejectsWrongScope(t *testing.T) {
	identity, _ := GenerateIdentity()
	token, _, err := MintRelayToken(identity, "mate-1", RelayScopePairing, "", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRelayToken(token, identity.SigningPublic, "mate-1", []RelayTokenScope{RelayScopeMate, RelayScopeDevice}, "device-1", time.Now()); err == nil {
		t.Fatal("pairing-scope token accepted where only mate/device scope is allowed")
	}
}

func TestVerifyRelayTokenRejectsMismatchedMateID(t *testing.T) {
	identity, _ := GenerateIdentity()
	token, _, err := MintRelayToken(identity, "mate-1", RelayScopeMate, "", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRelayToken(token, identity.SigningPublic, "mate-2", []RelayTokenScope{RelayScopeMate}, "", time.Now()); err == nil {
		t.Fatal("token issued for mate-1 accepted as mate-2")
	}
}

func TestVerifyRelayTokenRejectsMismatchedDeviceID(t *testing.T) {
	identity, _ := GenerateIdentity()
	token, _, err := MintRelayToken(identity, "mate-1", RelayScopeDevice, "device-1", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRelayToken(token, identity.SigningPublic, "mate-1", []RelayTokenScope{RelayScopeDevice}, "device-2", time.Now()); err == nil {
		t.Fatal("device token accepted for a different device_id")
	}
}

func TestVerifyRelayTokenWildcardDeviceIDAcceptedForPairingScope(t *testing.T) {
	identity, _ := GenerateIdentity()
	token, _, err := MintRelayToken(identity, "mate-1", RelayScopePairing, "", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for _, deviceID := range []string{"device-1", "any-other-device"} {
		if _, err := VerifyRelayToken(token, identity.SigningPublic, "mate-1", []RelayTokenScope{RelayScopePairing}, deviceID, time.Now()); err != nil {
			t.Fatalf("wildcard pairing token rejected for device_id %q: %v", deviceID, err)
		}
	}
}

func TestVerifyRelayTokenRejectsWrongSigner(t *testing.T) {
	identity, _ := GenerateIdentity()
	attacker, _ := GenerateIdentity()
	token, _, err := MintRelayToken(identity, "mate-1", RelayScopeMate, "", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRelayToken(token, attacker.SigningPublic, "mate-1", []RelayTokenScope{RelayScopeMate}, "", time.Now()); err == nil {
		t.Fatal("token verified against the wrong mate's public key")
	}
}

// flipRune flips the first character of a base64url segment, producing a
// different decoded byte string. Deliberately not the last character: the
// final base64 symbol of a non-multiple-of-4-length segment can carry
// don't-care padding bits that Go's decoder ignores, so a flip there can
// decode to the *same* bytes and silently fail to tamper anything. The
// first symbol's bits are always significant.
func flipRune(segment string) string {
	if segment == "" {
		return "a"
	}
	runes := []rune(segment)
	if runes[0] == 'a' {
		runes[0] = 'b'
	} else {
		runes[0] = 'a'
	}
	return string(runes)
}
