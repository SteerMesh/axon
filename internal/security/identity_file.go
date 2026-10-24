package security

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/flynn/noise"
	"golang.org/x/crypto/curve25519"
)

type identityFile struct {
	SigningPrivate string `json:"signing_private"`
	NoisePrivate   string `json:"noise_private"`
}

func LoadOrCreateIdentity(path string) (Identity, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		return decodeIdentity(data)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return Identity{}, err
	}
	identity, err := GenerateIdentity()
	if err != nil {
		return Identity{}, err
	}
	encoded, err := json.Marshal(identityFile{
		SigningPrivate: base64.RawStdEncoding.EncodeToString(identity.SigningPrivate),
		NoisePrivate:   base64.RawStdEncoding.EncodeToString(identity.Noise.Private),
	})
	if err != nil {
		return Identity{}, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return Identity{}, err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".identity-*")
	if err != nil {
		return Identity{}, err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return Identity{}, err
	}
	if _, err := temporary.Write(encoded); err != nil {
		temporary.Close()
		return Identity{}, err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return Identity{}, err
	}
	if err := temporary.Close(); err != nil {
		return Identity{}, err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return Identity{}, err
	}
	return identity, nil
}

func decodeIdentity(data []byte) (Identity, error) {
	var stored identityFile
	if err := json.Unmarshal(data, &stored); err != nil {
		return Identity{}, fmt.Errorf("decode identity file: %w", err)
	}
	signingPrivate, err := base64.RawStdEncoding.DecodeString(stored.SigningPrivate)
	if err != nil || len(signingPrivate) != ed25519.PrivateKeySize {
		return Identity{}, errors.New("identity file has an invalid signing key")
	}
	noisePrivate, err := base64.RawStdEncoding.DecodeString(stored.NoisePrivate)
	if err != nil || len(noisePrivate) != curve25519.ScalarSize {
		return Identity{}, errors.New("identity file has an invalid Noise key")
	}
	noisePublic, err := curve25519.X25519(noisePrivate, curve25519.Basepoint)
	if err != nil {
		return Identity{}, fmt.Errorf("derive Noise public key: %w", err)
	}
	private := ed25519.PrivateKey(append([]byte(nil), signingPrivate...))
	return Identity{
		SigningPrivate: private,
		SigningPublic:  append(ed25519.PublicKey(nil), private.Public().(ed25519.PublicKey)...),
		Noise:          noise.DHKey{Private: append([]byte(nil), noisePrivate...), Public: noisePublic},
	}, nil
}
