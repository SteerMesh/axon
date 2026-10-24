package domain

import "time"

type SessionState string

const (
	StateIdle            SessionState = "idle"
	StateRunning         SessionState = "running"
	StateWaitingForInput SessionState = "waiting_input"
	StateFinished        SessionState = "finished"
	StateError           SessionState = "error"
)

type Permission string

const (
	PermissionInteractive  Permission = "interactive"
	PermissionReadOnly     Permission = "read_only"
	PermissionConfirmInput Permission = "approve_to_type"
)

type Session struct {
	ID             string                `json:"id"`
	Name           string                `json:"name"`
	Target         TargetSpec            `json:"target"`
	State          SessionState          `json:"state"`
	ExitCode       *int                  `json:"exit_code,omitempty"`
	DefaultPerm    Permission            `json:"default_permission"`
	DevicePerms    map[string]Permission `json:"device_permissions,omitempty"`
	StreamEpoch    string                `json:"stream_epoch"`
	CreatedAt      time.Time             `json:"created_at"`
	LastActivityAt time.Time             `json:"last_activity_at"`
}

type TargetSpec struct {
	Kind string            `json:"kind"`
	Args []string          `json:"args,omitempty"`
	Cwd  string            `json:"cwd,omitempty"`
	Env  map[string]string `json:"-"`
	Cols uint16            `json:"cols,omitempty"`
	Rows uint16            `json:"rows,omitempty"`
}

func (s Session) PermissionFor(deviceID string) Permission {
	if p, ok := s.DevicePerms[deviceID]; ok {
		return p
	}
	return s.DefaultPerm
}
