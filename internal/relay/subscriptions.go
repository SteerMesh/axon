package relay

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// Subscription is a browser Push API subscription for one device belonging
// to one mate. The relay stores only what it needs to address a push
// service; it never stores session content.
type Subscription struct {
	MateID    string
	DeviceID  string
	Endpoint  string
	P256dh    string
	Auth      string
	CreatedAt time.Time
}

// SubscriptionStore persists Web Push subscriptions keyed by (mate_id,
// device_id) so the relay can wake a backgrounded PWA when it has no
// connected peer for that device.
type SubscriptionStore struct{ db *sql.DB }

func OpenSubscriptionStore(path string) (*SubscriptionStore, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	store := &SubscriptionStore{db: db}
	if err := store.migrate(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

func (s *SubscriptionStore) migrate(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
PRAGMA journal_mode = WAL;
CREATE TABLE IF NOT EXISTS push_subscriptions (
  mate_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  endpoint TEXT NOT NULL,
  p256dh TEXT NOT NULL,
  auth TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY(mate_id, device_id)
);
`)
	return err
}

// Upsert replaces any existing subscription for (mate_id, device_id). A
// device re-subscribing (e.g. after the browser rotates its push endpoint)
// should always win over a stale row.
func (s *SubscriptionStore) Upsert(ctx context.Context, sub Subscription) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO push_subscriptions(mate_id, device_id, endpoint, p256dh, auth, created_at)
VALUES(?, ?, ?, ?, ?, ?)
ON CONFLICT(mate_id, device_id) DO UPDATE SET
  endpoint=excluded.endpoint, p256dh=excluded.p256dh, auth=excluded.auth, created_at=excluded.created_at`,
		sub.MateID, sub.DeviceID, sub.Endpoint, sub.P256dh, sub.Auth, sub.CreatedAt.Unix())
	return err
}

// Get returns sql.ErrNoRows if no subscription exists for the device.
func (s *SubscriptionStore) Get(ctx context.Context, mateID, deviceID string) (Subscription, error) {
	var sub Subscription
	var createdAt int64
	err := s.db.QueryRowContext(ctx,
		`SELECT mate_id, device_id, endpoint, p256dh, auth, created_at FROM push_subscriptions WHERE mate_id=? AND device_id=?`,
		mateID, deviceID).
		Scan(&sub.MateID, &sub.DeviceID, &sub.Endpoint, &sub.P256dh, &sub.Auth, &createdAt)
	if err != nil {
		return Subscription{}, err
	}
	sub.CreatedAt = time.Unix(createdAt, 0).UTC()
	return sub, nil
}

func (s *SubscriptionStore) Delete(ctx context.Context, mateID, deviceID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM push_subscriptions WHERE mate_id=? AND device_id=?`, mateID, deviceID)
	return err
}

func (s *SubscriptionStore) Close() error { return s.db.Close() }
