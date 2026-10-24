package security

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestIdentityPersistsWithRestrictedPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")
	first, err := LoadOrCreateIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreateIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Noise.Private, second.Noise.Private) || !bytes.Equal(first.SigningPrivate, second.SigningPrivate) {
		t.Fatal("identity changed after reload")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("identity permissions are %o", info.Mode().Perm())
	}
}

func TestIdentityFileRejectsCorruptContent(t *testing.T) {
	for _, content := range []string{
		"not-json",
		`{"signing_private":"bad","noise_private":"bad"}`,
		`{"signing_private":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","noise_private":"bad"}`,
	} {
		path := filepath.Join(t.TempDir(), "identity.json")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadOrCreateIdentity(path); err == nil {
			t.Fatalf("corrupt content accepted: %q", content)
		}
	}
}

func TestIdentityFileReadAndCreateFailures(t *testing.T) {
	directory := t.TempDir()
	if _, err := LoadOrCreateIdentity(directory); err == nil {
		t.Fatal("directory was accepted as an identity file")
	}
	parent := filepath.Join(t.TempDir(), "regular-file")
	if err := os.WriteFile(parent, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateIdentity(filepath.Join(parent, "identity.json")); err == nil {
		t.Fatal("identity created below a regular file")
	}
}
