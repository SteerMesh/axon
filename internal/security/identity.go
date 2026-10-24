package security

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/flynn/noise"
)

type Identity struct {
	SigningPublic  ed25519.PublicKey
	SigningPrivate ed25519.PrivateKey
	Noise          noise.DHKey
}

func GenerateIdentity() (Identity, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Identity{}, fmt.Errorf("generate signing key: %w", err)
	}
	dh, err := noise.DH25519.GenerateKeypair(rand.Reader)
	if err != nil {
		return Identity{}, fmt.Errorf("generate Noise key: %w", err)
	}
	return Identity{SigningPublic: public, SigningPrivate: private, Noise: dh}, nil
}

func PublicKeyString(key []byte) string {
	return base64.RawURLEncoding.EncodeToString(key)
}

func IdentityID(identity Identity) string {
	digest := sha256.Sum256(identity.SigningPublic)
	return "axon-" + base64.RawURLEncoding.EncodeToString(digest[:12])
}
