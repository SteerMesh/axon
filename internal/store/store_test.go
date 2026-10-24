package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/SteerMesh/axon/internal/authz"
	"github.com/SteerMesh/axon/internal/security"
)

func TestDeviceRevocationAndHashedAudit(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "axon.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	record := security.DeviceRecord{MateID: "mate", DeviceID: "device", DeviceSigningKey: []byte("sign"), DeviceNoiseKey: []byte("noise"), PairedAt: time.Now(), MateSignature: []byte("sig")}
	if err := store.PutDevice(context.Background(), record, authz.RoleOwner); err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeDevice(context.Background(), "device", time.Now()); err != nil {
		t.Fatal(err)
	}
	device, err := store.Device(context.Background(), "device")
	if err != nil || device.RevokedAt == nil {
		t.Fatalf("device was not revoked: %+v, %v", device, err)
	}
	devices, err := store.Devices(context.Background())
	if err != nil || len(devices) != 1 || devices[0].RevokedAt == nil {
		t.Fatalf("revoked device listing=%+v err=%v", devices, err)
	}
	secret := []byte("do not store this prompt")
	if err := store.Audit(context.Background(), AuditEntry{OccurredAt: time.Now(), DeviceID: "device", SessionID: "session", Action: "session.input", Outcome: "accepted"}, secret); err != nil {
		t.Fatal(err)
	}
	entries, err := store.AuditEntries(context.Background(), "session")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].InputHash == "" || entries[0].InputHash == string(secret) {
		t.Fatalf("unexpected audit entry: %+v", entries)
	}
}

func TestStoreDeviceListingAndValidation(t *testing.T) {
	persistent, err := Open(filepath.Join(t.TempDir(), "axon.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer persistent.Close()
	record := security.DeviceRecord{MateID: "mate", DeviceID: "device", DeviceSigningKey: []byte("sign"), DeviceNoiseKey: []byte("noise"), PairedAt: time.Now(), MateSignature: []byte("sig")}
	if err := persistent.PutDevice(context.Background(), record, authz.Role("admin")); err == nil {
		t.Fatal("invalid role accepted")
	}
	if err := persistent.PutDevice(context.Background(), record, authz.RoleViewer); err != nil {
		t.Fatal(err)
	}
	devices, err := persistent.Devices(context.Background())
	if err != nil || len(devices) != 1 || devices[0].Role != authz.RoleViewer {
		t.Fatalf("devices=%+v err=%v", devices, err)
	}
	if _, err := persistent.Device(context.Background(), "missing"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("missing device error=%v", err)
	}
	if err := persistent.RevokeDevice(context.Background(), "missing", time.Now()); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("missing revoke error=%v", err)
	}
	if err := persistent.PutDevice(context.Background(), record, authz.RoleOwner); err != nil {
		t.Fatal(err)
	}
	device, err := persistent.Device(context.Background(), "device")
	if err != nil || device.Role != authz.RoleOwner || device.RevokedAt != nil {
		t.Fatalf("upserted device=%+v err=%v", device, err)
	}
}

func TestStoreOpenFailure(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(parent, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(filepath.Join(parent, "axon.db")); err == nil {
		t.Fatal("store opened below regular file")
	}
}
