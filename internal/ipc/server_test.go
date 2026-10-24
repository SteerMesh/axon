//go:build unix

package ipc

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/SteerMesh/axon/internal/domain"
	"github.com/SteerMesh/axon/internal/session"
	"github.com/SteerMesh/axon/internal/target"
)

type testAdapter struct{}
type testProcess struct{ reader *io.PipeReader }

func (testAdapter) Kind() string { return "test" }
func (testAdapter) Spawn(context.Context, domain.TargetSpec) (target.Process, error) {
	r, _ := io.Pipe()
	return &testProcess{reader: r}, nil
}
func (p *testProcess) Write(data []byte) (int, error) { return len(data), nil }
func (p *testProcess) Close() error                   { return p.reader.Close() }
func (p *testProcess) Output() io.Reader              { return p.reader }
func (p *testProcess) Resize(uint16, uint16) error    { return nil }
func (p *testProcess) Signal(target.Signal) error     { return nil }
func (p *testProcess) Wait() (int, error)             { select {} }

func TestServerSecuresSocketAndServesRequests(t *testing.T) {
	manager := session.NewManager(1024, testAdapter{})
	dir, err := os.MkdirTemp("/tmp", "axon-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "agent.sock")
	server, err := Listen(manager, path)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client := NewClient(path)
	var health map[string]string
	if err := client.Call("health", nil, &health); err != nil {
		t.Fatal(err)
	}
	if health["status"] != "ok" {
		t.Fatalf("unexpected health response: %+v", health)
	}
}
