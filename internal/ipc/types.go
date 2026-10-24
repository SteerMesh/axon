package ipc

import (
	"encoding/json"

	"github.com/SteerMesh/axon/internal/domain"
	"github.com/SteerMesh/axon/internal/session"
	"github.com/SteerMesh/axon/internal/store"
)

type Request struct {
	ID     string          `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

type Response struct {
	ID     string          `json:"id"`
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *RPCError       `json:"error,omitempty"`
}

type RPCError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type CreateParams struct {
	Name       string            `json:"name,omitempty"`
	Target     domain.TargetSpec `json:"target"`
	Permission domain.Permission `json:"permission"`
}

type InputParams struct {
	SessionID      string `json:"session_id"`
	DeviceID       string `json:"device_id"`
	IdempotencyKey string `json:"idempotency_key"`
	Data           []byte `json:"data"`
}

type ResizeParams struct {
	SessionID string `json:"session_id"`
	Cols      uint16 `json:"cols"`
	Rows      uint16 `json:"rows"`
}

type SignalParams struct {
	SessionID string `json:"session_id"`
	Signal    string `json:"signal"`
}

type AttachParams struct {
	SessionID string `json:"session_id"`
	FromSeq   uint64 `json:"from_seq,omitempty"`
}

type AttachResult struct {
	Replay session.Replay `json:"replay"`
}

type Event struct {
	Type  string        `json:"type"`
	Chunk session.Chunk `json:"chunk"`
}

type PairingIssueParams struct {
	TTLSeconds int64 `json:"ttl_seconds"`
}

type DeviceRevokeParams struct {
	DeviceID string `json:"device_id"`
}

type DeviceListResult struct {
	Devices []store.Device `json:"devices"`
}
