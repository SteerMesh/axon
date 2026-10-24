package meshcli

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestDiscover(t *testing.T) {
	executable := filepath.Join(t.TempDir(), "mesh-test")
	script := `#!/bin/sh
printf '[{"Workspace":{"name":"steermesh-team"}}]'
`
	if err := os.WriteFile(executable, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	options, err := Discover(context.Background(), executable)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(options.Workspaces, []string{"steermesh-team"}) || len(options.Targets) != 6 {
		t.Fatalf("unexpected options: %+v", options)
	}
	if _, err := Discover(context.Background(), filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing Mesh executable was accepted")
	}
}

func TestParseWorkspaces(t *testing.T) {
	got, err := parseWorkspaces([]byte(`[
		{"Workspace":{"name":"steermesh-team"}},
		{"Workspace":{"name":"default"}},
		{"Workspace":{"name":"bad workspace"}}
	]`))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"default", "steermesh-team"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("workspaces = %v, want %v", got, want)
	}
	if _, err := parseWorkspaces([]byte(`{`)); err == nil {
		t.Fatal("invalid JSON was accepted")
	}
}

func TestOptionsBuildArgs(t *testing.T) {
	options := Options{Workspaces: []string{"default", "steermesh-team"}, Targets: []string{"kiro", "codex"}}
	got, err := options.BuildArgs("steermesh-team", "codex")
	if err != nil || !reflect.DeepEqual(got, []string{"--ws", "steermesh-team", "--target", "codex"}) {
		t.Fatalf("args = %v, err = %v", got, err)
	}
	if got, err := options.BuildArgs("", ""); err != nil || len(got) != 0 {
		t.Fatalf("empty selection = %v, err = %v", got, err)
	}
	for _, test := range []struct{ workspace, target string }{
		{"missing", "codex"},
		{"bad workspace", "codex"},
		{"default", "shell"},
	} {
		if _, err := options.BuildArgs(test.workspace, test.target); err == nil {
			t.Fatalf("invalid selection was accepted: %+v", test)
		}
	}
}
