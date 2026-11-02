package relay

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSubscriptionStoreUpsertGetDelete(t *testing.T) {
	store, err := OpenSubscriptionStore(filepath.Join(t.TempDir(), "push.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	ctx := context.Background()
	sub := Subscription{
		MateID: "mate-1", DeviceID: "device-1", Endpoint: "https://push.example/ep1",
		P256dh: "p256dh-1", Auth: "auth-1", CreatedAt: time.Now(),
	}
	if err := store.Upsert(ctx, sub); err != nil {
		t.Fatal(err)
	}
	got, err := store.Get(ctx, "mate-1", "device-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Endpoint != sub.Endpoint || got.P256dh != sub.P256dh || got.Auth != sub.Auth {
		t.Fatalf("unexpected subscription: %+v", got)
	}

	// Upsert on the same key replaces, it doesn't duplicate.
	updated := sub
	updated.Endpoint = "https://push.example/ep2"
	if err := store.Upsert(ctx, updated); err != nil {
		t.Fatal(err)
	}
	got, err = store.Get(ctx, "mate-1", "device-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Endpoint != updated.Endpoint {
		t.Fatalf("upsert did not replace endpoint: %+v", got)
	}

	if err := store.Delete(ctx, "mate-1", "device-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(ctx, "mate-1", "device-1"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected sql.ErrNoRows after delete, got %v", err)
	}
}

func TestOpenSubscriptionStoreFailsWhenParentDirCannotBeCreated(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSubscriptionStore(filepath.Join(blocker, "sub", "push.db")); err == nil {
		t.Fatal("expected an error when the parent path is not a directory")
	}
}

func TestSubscriptionStoreGetMissing(t *testing.T) {
	store, err := OpenSubscriptionStore(filepath.Join(t.TempDir(), "push.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.Get(context.Background(), "mate", "device"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected sql.ErrNoRows, got %v", err)
	}
}

func TestSubscriptionStoreDeleteMissingIsNoop(t *testing.T) {
	store, err := OpenSubscriptionStore(filepath.Join(t.TempDir(), "push.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Delete(context.Background(), "mate", "device"); err != nil {
		t.Fatalf("delete of missing row should not error: %v", err)
	}
}

func TestSubscriptionStoreIsolatesDevicesAndMates(t *testing.T) {
	store, err := OpenSubscriptionStore(filepath.Join(t.TempDir(), "push.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	if err := store.Upsert(ctx, Subscription{MateID: "mate-1", DeviceID: "device-1", Endpoint: "e1", P256dh: "p1", Auth: "a1", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := store.Upsert(ctx, Subscription{MateID: "mate-1", DeviceID: "device-2", Endpoint: "e2", P256dh: "p2", Auth: "a2", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(ctx, "mate-1", "device-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(ctx, "mate-1", "device-2"); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(ctx, "mate-1", "device-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(ctx, "mate-1", "device-2"); err != nil {
		t.Fatalf("unrelated device should be unaffected: %v", err)
	}
}
