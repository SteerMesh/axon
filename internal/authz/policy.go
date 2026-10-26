package authz

import (
	"errors"

	"github.com/SteerMesh/axon/internal/domain"
)

type Role string

const (
	RoleOwner  Role = "owner"
	RoleViewer Role = "viewer"
)

type Operation string

const (
	OperationList   Operation = "sessions.list"
	OperationAttach Operation = "session.attach"
	OperationInput  Operation = "session.input"
	OperationResize Operation = "session.resize"
	OperationSignal Operation = "session.signal"
	OperationCreate Operation = "session.create"
	OperationRemove Operation = "session.remove"
)

var (
	ErrUnauthorized       = errors.New("operation is not authorized")
	ErrReadOnly           = errors.New("session is read-only")
	ErrConfirmationNeeded = errors.New("input confirmation is required")
)

func Authorize(role Role, permission domain.Permission, operation Operation, confirmed bool) error {
	if operation == OperationList || operation == OperationAttach || operation == OperationResize {
		return nil
	}
	if role != RoleOwner {
		return ErrUnauthorized
	}
	if operation == OperationCreate {
		return nil
	}
	if permission == domain.PermissionReadOnly {
		return ErrReadOnly
	}
	if operation == OperationInput && permission == domain.PermissionConfirmInput && !confirmed {
		return ErrConfirmationNeeded
	}
	return nil
}
