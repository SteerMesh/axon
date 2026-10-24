package target

import (
	"context"
	"io"

	"github.com/SteerMesh/axon/internal/domain"
)

type Signal string

const (
	SignalInterrupt Signal = "INT"
	SignalTerminate Signal = "TERM"
	SignalKill      Signal = "KILL"
)

type Process interface {
	io.WriteCloser
	Output() io.Reader
	Resize(cols, rows uint16) error
	Signal(signal Signal) error
	Wait() (int, error)
}

type Adapter interface {
	Kind() string
	Spawn(context.Context, domain.TargetSpec) (Process, error)
}

type StateObservation struct {
	State      domain.SessionState
	Confidence float64
	Source     string
}

type StateDetector interface {
	Detect(recent []byte) (StateObservation, bool)
}
