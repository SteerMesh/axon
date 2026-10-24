//go:build unix

package ipc

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/SteerMesh/axon/internal/authz"
	"github.com/SteerMesh/axon/internal/domain"
	"github.com/SteerMesh/axon/internal/security"
	"github.com/SteerMesh/axon/internal/session"
	"github.com/SteerMesh/axon/internal/store"
	"github.com/SteerMesh/axon/internal/target"
)

type rpcAdapter struct{ process *rpcProcess }

func (a rpcAdapter) Kind() string { return "rpc" }
func (a rpcAdapter) Spawn(context.Context, domain.TargetSpec) (target.Process, error) {
	return a.process, nil
}

type rpcProcess struct {
	r     *io.PipeReader
	w     *io.PipeWriter
	mu    sync.Mutex
	input []byte
}

func newRPCProcess() *rpcProcess {
	r, w := io.Pipe()
	return &rpcProcess{r: r, w: w}
}

func (p *rpcProcess) Write(data []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.input = append(p.input, data...)
	return len(data), nil
}
func (p *rpcProcess) Close() error      { return p.r.Close() }
func (p *rpcProcess) Output() io.Reader { return p.r }
func (p *rpcProcess) Resize(cols, rows uint16) error {
	if cols == 0 || rows == 0 {
		return io.ErrShortBuffer
	}
	return nil
}
func (p *rpcProcess) Signal(signal target.Signal) error {
	if signal == target.Signal("bad") {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (p *rpcProcess) Wait() (int, error) { select {} }

func TestIPCCommandAndSubscriptionMatrix(t *testing.T) {
	process := newRPCProcess()
	manager := session.NewManager(8, rpcAdapter{process: process})
	identity, err := security.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	pairing := security.NewPairingManager("mate", "wss://relay", identity)
	persistent, err := store.Open(filepath.Join(t.TempDir(), "axon.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer persistent.Close()
	record := security.DeviceRecord{MateID: "mate", DeviceID: "device", DeviceSigningKey: []byte("sign"), DeviceNoiseKey: []byte("noise"), PairedAt: time.Now(), MateSignature: []byte("sig")}
	if err := persistent.PutDevice(context.Background(), record, authz.RoleOwner); err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("/tmp", "axon-ipc-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "agent.sock")
	if err := os.Chmod(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	server, err := ListenWithOptions(manager, path, Options{Pairing: pairing, Store: persistent})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client := NewClient(path)

	var created domain.Session
	if err := client.Call("session.create", CreateParams{Name: "rpc", Target: domain.TargetSpec{Kind: "rpc"}, Permission: domain.PermissionInteractive}, &created); err != nil {
		t.Fatal(err)
	}
	if err := client.Call("session.input", InputParams{SessionID: created.ID, DeviceID: "device", IdempotencyKey: "1", Data: []byte("hello")}, nil); err != nil {
		t.Fatal(err)
	}
	if err := client.Call("session.resize", ResizeParams{SessionID: created.ID, Cols: 100, Rows: 40}, nil); err != nil {
		t.Fatal(err)
	}
	if err := client.Call("session.signal", SignalParams{SessionID: created.ID, Signal: string(target.SignalInterrupt)}, nil); err != nil {
		t.Fatal(err)
	}
	var sessions []domain.Session
	if err := client.Call("sessions.list", nil, &sessions); err != nil || len(sessions) != 1 {
		t.Fatalf("sessions=%+v err=%v", sessions, err)
	}
	var bundle security.PairingBundle
	if err := client.Call("pairing.issue", PairingIssueParams{TTLSeconds: 60}, &bundle); err != nil || bundle.MateID != "mate" {
		t.Fatalf("bundle=%+v err=%v", bundle, err)
	}
	var devices DeviceListResult
	if err := client.Call("devices.list", nil, &devices); err != nil || len(devices.Devices) != 1 {
		t.Fatalf("devices=%+v err=%v", devices, err)
	}
	if err := client.Call("devices.revoke", DeviceRevokeParams{DeviceID: "device"}, nil); err != nil {
		t.Fatal(err)
	}

	replay, events, cancel, err := client.Subscribe(AttachParams{SessionID: created.ID})
	if err != nil || len(replay.Chunks) != 0 {
		t.Fatalf("replay=%+v err=%v", replay, err)
	}
	defer cancel()
	if _, err := process.w.Write([]byte("live")); err != nil {
		t.Fatal(err)
	}
	select {
	case event := <-events:
		if event.Type != "session.output" || string(event.Chunk.Data) != "live" {
			t.Fatalf("event=%+v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for IPC event")
	}

	for _, call := range []struct {
		method string
		params any
	}{
		{"session.create", nil}, {"session.input", InputParams{SessionID: "missing", IdempotencyKey: "x", Data: []byte("x")}},
		{"session.resize", ResizeParams{SessionID: created.ID}}, {"session.signal", SignalParams{SessionID: created.ID, Signal: "bad"}},
		{"pairing.issue", PairingIssueParams{TTLSeconds: 0}}, {"devices.revoke", DeviceRevokeParams{}}, {"unknown", nil},
	} {
		if err := client.Call(call.method, call.params, nil); err == nil {
			t.Fatalf("%s unexpectedly succeeded", call.method)
		}
	}
}

func TestIPCConfigurationAndMalformedRequests(t *testing.T) {
	manager := session.NewManager(16)
	dir, err := os.MkdirTemp("/tmp", "axon-ipc-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "agent.sock")
	if err := os.Chmod(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	server, err := Listen(manager, path)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client := NewClient(path)
	if err := client.Call("health", make(chan int), nil); err == nil {
		t.Fatal("unencodable request parameters accepted")
	}
	if err := client.Call("pairing.issue", PairingIssueParams{TTLSeconds: 1}, nil); err == nil || !strings.Contains(err.Error(), "not_configured") {
		t.Fatalf("pairing error=%v", err)
	}
	if err := client.Call("devices.list", nil, nil); err == nil || !strings.Contains(err.Error(), "not_configured") {
		t.Fatalf("devices error=%v", err)
	}
	if _, _, _, err := client.Subscribe(AttachParams{SessionID: "missing"}); err == nil {
		t.Fatal("missing subscription succeeded")
	}

	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("not-json\n")); err != nil {
		t.Fatal(err)
	}
	var response Response
	if err := json.NewDecoder(conn).Decode(&response); err != nil || response.Error == nil || response.Error.Code != "invalid_message" {
		t.Fatalf("response=%+v err=%v", response, err)
	}

	if _, err := DefaultSocketPath(); err != nil {
		t.Fatal(err)
	}
	nonSocket := filepath.Join(t.TempDir(), "existing")
	if err := os.WriteFile(nonSocket, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := prepareSocket(nonSocket); err == nil {
		t.Fatal("non-socket was replaced")
	}
	openDir := filepath.Join(t.TempDir(), "open")
	if err := os.Mkdir(openDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := prepareSocket(filepath.Join(openDir, "agent.sock")); err == nil {
		t.Fatal("insecure directory accepted")
	}
	parentFile := filepath.Join(t.TempDir(), "parent")
	if err := os.WriteFile(parentFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := prepareSocket(filepath.Join(parentFile, "agent.sock")); err == nil {
		t.Fatal("socket directory below a file accepted")
	}
	staleDir, err := os.MkdirTemp("/tmp", "axon-stale-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(staleDir) })
	stalePath := filepath.Join(staleDir, "agent.sock")
	listener, err := net.Listen("unix", stalePath)
	if err != nil {
		t.Fatal(err)
	}
	listener.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = listener.Close()
	if err := prepareSocket(stalePath); err != nil {
		t.Fatalf("stale socket was not removed: %v", err)
	}
}

func TestResponseHelpers(t *testing.T) {
	if response := resultResponse("id", make(chan int)); response.Error == nil || response.Error.Code != "internal" {
		t.Fatalf("response=%+v", response)
	}
	if response := errorResponseDetails("id", "gap", "lost", map[string]int{"min": 2}); response.OK || len(response.Result) == 0 {
		t.Fatalf("response=%+v", response)
	}
	for _, test := range []struct {
		err  error
		code string
	}{
		{session.ErrNotFound, "not_found"}, {session.ErrReadOnly, "read_only"}, {session.ErrDuplicate, "conflict"}, {io.ErrUnexpectedEOF, "internal"},
	} {
		if got := mapError("id", test.err); got.Error == nil || got.Error.Code != test.code {
			t.Fatalf("mapError(%v)=%+v", test.err, got)
		}
	}
}

func TestAttachReportsReplayGapAndInvalidParams(t *testing.T) {
	process := newRPCProcess()
	manager := session.NewManager(3, rpcAdapter{process: process})
	created, err := manager.Create(context.Background(), "gap", domain.TargetSpec{Kind: "rpc"}, domain.PermissionInteractive)
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("/tmp", "axon-attach-")
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
	if _, err := process.w.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	waitForSequence(t, manager, created.ID, 1)
	if _, err := process.w.Write([]byte("def")); err != nil {
		t.Fatal(err)
	}
	waitForSequence(t, manager, created.ID, 2)
	if _, _, _, err := NewClient(path).Subscribe(AttachParams{SessionID: created.ID, FromSeq: 1}); err == nil || !strings.Contains(err.Error(), "replay_gap") {
		t.Fatalf("gap error=%v", err)
	}

	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := json.NewEncoder(conn).Encode(Request{ID: "bad", Method: "session.attach"}); err != nil {
		t.Fatal(err)
	}
	var response Response
	if err := json.NewDecoder(conn).Decode(&response); err != nil || response.Error == nil || response.Error.Code != "invalid_message" {
		t.Fatalf("response=%+v err=%v", response, err)
	}
}

func waitForSequence(t *testing.T, manager *session.Manager, id string, sequence uint64) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		replay, _ := manager.Replay(id, 0)
		if replay.MaxSeq >= sequence {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("sequence %d not observed", sequence)
}
