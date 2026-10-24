package domain

import "testing"

func TestSessionPermissionOverridesDefault(t *testing.T) {
	session := Session{DefaultPerm: PermissionReadOnly, DevicePerms: map[string]Permission{"owner": PermissionInteractive}}
	if session.PermissionFor("owner") != PermissionInteractive {
		t.Fatal("device override ignored")
	}
	if session.PermissionFor("viewer") != PermissionReadOnly {
		t.Fatal("default permission ignored")
	}
}
