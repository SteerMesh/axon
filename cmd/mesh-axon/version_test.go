package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

// runRootCommand executes the root command with args and returns everything
// it printed to stdout. Commands in this package write straight to
// os.Stdout (see identity_test.go's runIdentityCommand), so stdout itself
// has to be redirected to capture it — including cobra's own --version
// writer, which defaults to the command's out stream (stdout).
func runRootCommand(t *testing.T, args ...string) string {
	t.Helper()
	root := newRoot("")
	root.SetArgs(args)

	original := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = writer

	done := make(chan struct{})
	var output string
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, reader)
		output = buf.String()
		close(done)
	}()

	runErr := root.Execute()
	_ = writer.Close()
	os.Stdout = original
	<-done
	if runErr != nil {
		t.Fatalf("command %v failed: %v", args, runErr)
	}
	return output
}

// TestVersionCommandAndFlagMatchMeshProber pins the exact output format
// mesh's AxonVersion() prober (internal/ops/axon_install.go in
// github.com/SteerMesh/mesh) parses: it runs the binary with "version" then
// "--version", trims the result, and strips a "mesh-axon " prefix. Both
// paths here must produce "mesh-axon <version>" so that stripping the
// prefix leaves a non-empty version string.
func TestVersionCommandAndFlagMatchMeshProber(t *testing.T) {
	for _, args := range [][]string{{"version"}, {"--version"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			output := strings.TrimSpace(runRootCommand(t, args...))

			const prefix = "mesh-axon "
			if !strings.HasPrefix(output, prefix) {
				t.Fatalf("output %q does not start with %q (mesh's prober strips exactly this prefix)", output, prefix)
			}
			got := strings.TrimSpace(strings.TrimPrefix(output, prefix))
			if got == "" {
				t.Fatalf("version string was empty after stripping %q from %q", prefix, output)
			}
			if got != version {
				t.Fatalf("got version %q, want package-level var %q", got, version)
			}
		})
	}
}
