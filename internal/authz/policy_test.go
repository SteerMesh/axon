package authz

import (
	"errors"
	"testing"

	"github.com/SteerMesh/axon/internal/domain"
)

func TestAuthorizationMatrix(t *testing.T) {
	tests := []struct {
		name       string
		role       Role
		permission domain.Permission
		operation  Operation
		confirmed  bool
		want       error
	}{
		{"viewer can attach", RoleViewer, domain.PermissionInteractive, OperationAttach, false, nil},
		{"viewer cannot input", RoleViewer, domain.PermissionInteractive, OperationInput, true, ErrUnauthorized},
		{"owner cannot write read-only", RoleOwner, domain.PermissionReadOnly, OperationInput, true, ErrReadOnly},
		{"confirmation required", RoleOwner, domain.PermissionConfirmInput, OperationInput, false, ErrConfirmationNeeded},
		{"confirmed input", RoleOwner, domain.PermissionConfirmInput, OperationInput, true, nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := Authorize(test.role, test.permission, test.operation, test.confirmed); !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
		})
	}
}
