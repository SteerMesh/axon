package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/SteerMesh/axon/internal/authz"
	"github.com/SteerMesh/axon/internal/security"
	_ "modernc.org/sqlite"
)

type Store struct{ db *sql.DB }

type Device struct {
	Record    security.DeviceRecord
	Role      authz.Role
	RevokedAt *time.Time
}

type AuditEntry struct {
	OccurredAt time.Time
	DeviceID   string
	SessionID  string
	Action     string
	Outcome    string
	InputHash  string
}

func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	store := &Store{db: db}
	if err := store.migrate(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil && !errors.Is(err, os.ErrNotExist) {
		db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) migrate(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS devices (
  device_id TEXT PRIMARY KEY,
  mate_id TEXT NOT NULL,
  signing_key BLOB NOT NULL,
  noise_key BLOB NOT NULL,
  paired_at TEXT NOT NULL,
  mate_signature BLOB NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('owner', 'viewer')),
  revoked_at TEXT
);
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  occurred_at TEXT NOT NULL,
  device_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  action TEXT NOT NULL,
  outcome TEXT NOT NULL,
  input_hash TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS audit_session_time ON audit_log(session_id, occurred_at);
`)
	return err
}

func (s *Store) PutDevice(ctx context.Context, record security.DeviceRecord, role authz.Role) error {
	if role != authz.RoleOwner && role != authz.RoleViewer {
		return fmt.Errorf("invalid device role %q", role)
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO devices(device_id, mate_id, signing_key, noise_key, paired_at, mate_signature, role, revoked_at)
VALUES(?, ?, ?, ?, ?, ?, ?, NULL)
ON CONFLICT(device_id) DO UPDATE SET
  mate_id=excluded.mate_id, signing_key=excluded.signing_key, noise_key=excluded.noise_key,
  paired_at=excluded.paired_at, mate_signature=excluded.mate_signature, role=excluded.role, revoked_at=NULL`,
		record.DeviceID, record.MateID, record.DeviceSigningKey, record.DeviceNoiseKey,
		record.PairedAt.Format(time.RFC3339Nano), record.MateSignature, string(role))
	return err
}

func (s *Store) Device(ctx context.Context, id string) (Device, error) {
	var device Device
	var pairedAt string
	var revokedAt sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT device_id, mate_id, signing_key, noise_key, paired_at, mate_signature, role, revoked_at FROM devices WHERE device_id=?`, id).
		Scan(&device.Record.DeviceID, &device.Record.MateID, &device.Record.DeviceSigningKey, &device.Record.DeviceNoiseKey,
			&pairedAt, &device.Record.MateSignature, &device.Role, &revokedAt)
	if err != nil {
		return Device{}, err
	}
	device.Record.PairedAt, err = time.Parse(time.RFC3339Nano, pairedAt)
	if err != nil {
		return Device{}, err
	}
	if revokedAt.Valid {
		value, parseErr := time.Parse(time.RFC3339Nano, revokedAt.String)
		if parseErr != nil {
			return Device{}, parseErr
		}
		device.RevokedAt = &value
	}
	return device, nil
}

func (s *Store) RevokeDevice(ctx context.Context, id string, now time.Time) error {
	result, err := s.db.ExecContext(ctx, `UPDATE devices SET revoked_at=? WHERE device_id=? AND revoked_at IS NULL`, now.UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) Devices(ctx context.Context) ([]Device, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT device_id, mate_id, signing_key, noise_key, paired_at, mate_signature, role, revoked_at FROM devices ORDER BY paired_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var devices []Device
	for rows.Next() {
		var device Device
		var pairedAt string
		var revokedAt sql.NullString
		if err := rows.Scan(&device.Record.DeviceID, &device.Record.MateID, &device.Record.DeviceSigningKey, &device.Record.DeviceNoiseKey, &pairedAt, &device.Record.MateSignature, &device.Role, &revokedAt); err != nil {
			return nil, err
		}
		device.Record.PairedAt, err = time.Parse(time.RFC3339Nano, pairedAt)
		if err != nil {
			return nil, err
		}
		if revokedAt.Valid {
			value, parseErr := time.Parse(time.RFC3339Nano, revokedAt.String)
			if parseErr != nil {
				return nil, parseErr
			}
			device.RevokedAt = &value
		}
		devices = append(devices, device)
	}
	return devices, rows.Err()
}

func (s *Store) Audit(ctx context.Context, entry AuditEntry, input []byte) error {
	if len(input) > 0 {
		hash := sha256.Sum256(input)
		entry.InputHash = hex.EncodeToString(hash[:])
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO audit_log(occurred_at, device_id, session_id, action, outcome, input_hash) VALUES(?, ?, ?, ?, ?, ?)`,
		entry.OccurredAt.UTC().Format(time.RFC3339Nano), entry.DeviceID, entry.SessionID, entry.Action, entry.Outcome, entry.InputHash)
	return err
}

func (s *Store) AuditEntries(ctx context.Context, sessionID string) ([]AuditEntry, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT occurred_at, device_id, session_id, action, outcome, input_hash FROM audit_log WHERE session_id=? ORDER BY id`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var entries []AuditEntry
	for rows.Next() {
		var entry AuditEntry
		var occurred string
		if err := rows.Scan(&occurred, &entry.DeviceID, &entry.SessionID, &entry.Action, &entry.Outcome, &entry.InputHash); err != nil {
			return nil, err
		}
		entry.OccurredAt, err = time.Parse(time.RFC3339Nano, occurred)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, rows.Err()
}

func (s *Store) Close() error { return s.db.Close() }
