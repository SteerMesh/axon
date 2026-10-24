package templates

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCatalogUsesFixedServerSideArguments(t *testing.T) {
	path := filepath.Join(t.TempDir(), "templates.yaml")
	data := []byte("templates:\n  review:\n    target: claude\n    args: [--model, sonnet]\n    cwd: /work/project\n    permission: approve_to_type\n")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	catalog, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	spec, _, err := catalog.Resolve("review")
	if err != nil || len(spec.Args) != 2 || spec.Args[1] != "sonnet" {
		t.Fatalf("unexpected resolved template: %+v, %v", spec, err)
	}
	if _, _, err := catalog.Resolve("arbitrary-command"); err == nil {
		t.Fatal("unknown template was accepted")
	}
}

func TestCatalogRejectsInvalidFiles(t *testing.T) {
	for _, content := range []string{
		"templates: [",
		"unknown: true\n",
		"templates:\n  '':\n    target: shell\n    permission: interactive\n",
		"templates:\n  bad:\n    target: ''\n    permission: interactive\n",
		"templates:\n  bad:\n    target: shell\n    permission: root\n",
	} {
		path := filepath.Join(t.TempDir(), "templates.yaml")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Fatalf("invalid catalog accepted: %q", content)
		}
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Fatal("missing catalog accepted")
	}
}

func TestCatalogResolveReturnsDefensiveCopies(t *testing.T) {
	catalog := Catalog{Templates: map[string]Template{
		"safe": {Target: "shell", Args: []string{"one"}, Env: map[string]string{"A": "B"}, Permission: "interactive"},
	}}
	first, _, _ := catalog.Resolve("safe")
	first.Args[0] = "changed"
	first.Env["A"] = "changed"
	second, _, _ := catalog.Resolve("safe")
	if second.Args[0] != "one" || second.Env["A"] != "B" {
		t.Fatalf("catalog mutated: %+v", second)
	}
}
