package main

import (
	"bytes"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SteerMesh/axon/internal/security"
)

// runIdentityCommand executes newIdentityCommand with args and returns
// everything it printed to stdout. fmt.Printf/Println write straight to
// os.Stdout rather than cmd.OutOrStdout() (matching every other command in
// this file), so stdout itself has to be redirected to capture it.
func runIdentityCommand(t *testing.T, args ...string) string {
	t.Helper()
	command := newIdentityCommand()
	command.SetArgs(args)

	original := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = writer

	done := make(chan struct{})
	var output string
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, reader)
		output = buf.String()
		close(done)
	}()

	runErr := command.Execute()
	_ = writer.Close()
	os.Stdout = original
	<-done
	if runErr != nil {
		t.Fatalf("identity command failed: %v", runErr)
	}
	return output
}

func TestIdentityCommandCreatesIdentityAndPrintsMateIDAndKey(t *testing.T) {
	dataDir := t.TempDir()

	output := runIdentityCommand(t, "--data-dir", dataDir)

	if _, err := os.Stat(filepath.Join(dataDir, "identity.json")); err != nil {
		t.Fatalf("identity.json was not created: %v", err)
	}
	identity, err := security.LoadOrCreateIdentity(filepath.Join(dataDir, "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	wantMateID := security.IdentityID(identity)
	wantKey := security.PublicKeyString(identity.SigningPublic)

	if !strings.Contains(output, "Mate ID:    "+wantMateID) {
		t.Fatalf("output missing mate ID %q:\n%s", wantMateID, output)
	}
	if !strings.Contains(output, "Public key: "+wantKey) {
		t.Fatalf("output missing public key %q:\n%s", wantKey, output)
	}
	if !strings.Contains(output, "AXON_RELAY_MATE_KEYS fragment: "+wantMateID+"="+wantKey) {
		t.Fatalf("output missing AXON_RELAY_MATE_KEYS fragment:\n%s", output)
	}
}

func TestIdentityCommandIsStableAcrossRuns(t *testing.T) {
	dataDir := t.TempDir()

	first := runIdentityCommand(t, "--data-dir", dataDir)
	second := runIdentityCommand(t, "--data-dir", dataDir)

	if first != second {
		t.Fatalf("identity command regenerated the identity between runs:\nfirst:\n%s\nsecond:\n%s", first, second)
	}
}

func TestIdentityCommandMateIDOverride(t *testing.T) {
	dataDir := t.TempDir()

	output := runIdentityCommand(t, "--data-dir", dataDir, "--mate-id", "custom-mate")

	identity, err := security.LoadOrCreateIdentity(filepath.Join(dataDir, "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	wantKey := security.PublicKeyString(identity.SigningPublic)

	if !strings.Contains(output, "Mate ID:    custom-mate") {
		t.Fatalf("output did not reflect --mate-id override:\n%s", output)
	}
	if !strings.Contains(output, "AXON_RELAY_MATE_KEYS fragment: custom-mate="+wantKey) {
		t.Fatalf("fragment line did not reflect --mate-id override:\n%s", output)
	}
}

// TestIdentityCommandNeverPrintsPrivateKeys is the one hard requirement for
// this command: it must never leak SigningPrivate or Noise.Private, in any
// encoding, no matter how the output format changes in the future.
func TestIdentityCommandNeverPrintsPrivateKeys(t *testing.T) {
	dataDir := t.TempDir()

	output := runIdentityCommand(t, "--data-dir", dataDir)

	identity, err := security.LoadOrCreateIdentity(filepath.Join(dataDir, "identity.json"))
	if err != nil {
		t.Fatal(err)
	}

	forbidden := map[string][]byte{
		"signing private key": identity.SigningPrivate,
		"noise private key":   identity.Noise.Private,
	}
	for name, raw := range forbidden {
		if len(raw) == 0 {
			t.Fatalf("%s was empty, test would be meaningless", name)
		}
		if bytes.Contains([]byte(output), raw) {
			t.Fatalf("output leaked the %s as raw bytes", name)
		}
		for _, encoded := range []string{
			base64.StdEncoding.EncodeToString(raw),
			base64.RawStdEncoding.EncodeToString(raw),
			base64.URLEncoding.EncodeToString(raw),
			base64.RawURLEncoding.EncodeToString(raw),
		} {
			if strings.Contains(output, encoded) {
				t.Fatalf("output leaked the %s as base64: %s", name, encoded)
			}
		}
	}
}
