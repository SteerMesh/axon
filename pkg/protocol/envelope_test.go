package protocol

import (
	"strings"
	"testing"
	"time"
)

func TestEnvelopeValidate(t *testing.T) {
	valid := Envelope{Version: Version, ID: "request-1", Type: "sessions.list", Timestamp: time.Now()}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid envelope rejected: %v", err)
	}

	input := valid
	input.Type = "session.input"
	if err := input.Validate(); err == nil || !strings.Contains(err.Error(), "idempotency_key") {
		t.Fatalf("expected idempotency error, got %v", err)
	}

	oversized := valid
	oversized.Data = make([]byte, MaxPayloadLen+1)
	if err := oversized.Validate(); err == nil {
		t.Fatal("expected oversized payload rejection")
	}
}

func TestEnvelopeRequiredFields(t *testing.T) {
	valid := Envelope{Version: Version, ID: "id", Type: "health", Timestamp: time.Now()}
	for _, mutate := range []func(*Envelope){
		func(e *Envelope) { e.Version = 99 },
		func(e *Envelope) { e.ID = "" },
		func(e *Envelope) { e.Type = "" },
		func(e *Envelope) { e.Timestamp = time.Time{} },
	} {
		candidate := valid
		mutate(&candidate)
		if err := candidate.Validate(); err == nil {
			t.Fatalf("invalid envelope accepted: %+v", candidate)
		}
	}
}
