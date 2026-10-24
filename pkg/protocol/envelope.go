package protocol

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const (
	Version       = 1
	MaxPayloadLen = 64 << 10
)

type Envelope struct {
	Version        int             `json:"v"`
	ID             string          `json:"id"`
	ReplyTo        string          `json:"reply_to,omitempty"`
	Type           string          `json:"type"`
	SessionID      string          `json:"sid,omitempty"`
	Epoch          string          `json:"epoch,omitempty"`
	Sequence       uint64          `json:"seq,omitempty"`
	Timestamp      time.Time       `json:"ts"`
	IdempotencyKey string          `json:"idempotency_key,omitempty"`
	Data           json.RawMessage `json:"data,omitempty"`
}

func (e Envelope) Validate() error {
	if e.Version != Version {
		return fmt.Errorf("unsupported_version: got %d", e.Version)
	}
	if e.ID == "" {
		return errors.New("invalid_message: id is required")
	}
	if e.Type == "" {
		return errors.New("invalid_message: type is required")
	}
	if len(e.Data) > MaxPayloadLen {
		return fmt.Errorf("invalid_message: payload exceeds %d bytes", MaxPayloadLen)
	}
	if e.Timestamp.IsZero() {
		return errors.New("invalid_message: timestamp is required")
	}
	if e.Type == "session.input" && e.IdempotencyKey == "" {
		return errors.New("invalid_message: session.input requires idempotency_key")
	}
	return nil
}

type Error struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Details map[string]any `json:"details,omitempty"`
}
