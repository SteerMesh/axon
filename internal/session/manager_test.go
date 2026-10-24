package session

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/SteerMesh/axon/internal/domain"
	"github.com/SteerMesh/axon/internal/target"
)

type fakeAdapter struct{ process *fakeProcess }

func (f fakeAdapter) Kind() string { return "fake" }
func (f fakeAdapter) Spawn(context.Context, domain.TargetSpec) (target.Process, error) {
	return f.process, nil
}

type fakeProcess struct {
	outputR *io.PipeReader
	outputW *io.PipeWriter
	writes  bytes.Buffer
	mu      sync.Mutex
	done    chan struct{}
}

func newFakeProcess() *fakeProcess {
	r, w := io.Pipe()
	return &fakeProcess{outputR: r, outputW: w, done: make(chan struct{})}
}

func (p *fakeProcess) Write(data []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.writes.Write(data)
}
func (p *fakeProcess) Output() io.Reader           { return p.outputR }
func (p *fakeProcess) Resize(uint16, uint16) error { return nil }
func (p *fakeProcess) Signal(target.Signal) error  { return nil }
func (p *fakeProcess) Wait() (int, error)          { <-p.done; return 0, nil }
func (p *fakeProcess) Close() error                { return p.outputR.Close() }

type failingAdapter struct{}

func (failingAdapter) Kind() string { return "failing" }
func (failingAdapter) Spawn(context.Context, domain.TargetSpec) (target.Process, error) {
	return nil, io.ErrUnexpectedEOF
}

func TestManagerDeduplicatesInputAndEnforcesPermission(t *testing.T) {
	process := newFakeProcess()
	manager := NewManager(1024, fakeAdapter{process: process})
	s, err := manager.Create(context.Background(), "test", domain.TargetSpec{Kind: "fake"}, domain.PermissionInteractive)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Input(s.ID, "device", "key-1", []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := manager.Input(s.ID, "device", "key-1", []byte("hello")); err != nil {
		t.Fatal(err)
	}
	process.mu.Lock()
	got := process.writes.String()
	process.mu.Unlock()
	if got != "hello" {
		t.Fatalf("input was duplicated: %q", got)
	}

	process2 := newFakeProcess()
	readOnly := NewManager(1024, fakeAdapter{process: process2})
	ro, err := readOnly.Create(context.Background(), "read-only", domain.TargetSpec{Kind: "fake"}, domain.PermissionReadOnly)
	if err != nil {
		t.Fatal(err)
	}
	if err := readOnly.Input(ro.ID, "device", "key-2", []byte("no")); err != ErrReadOnly {
		t.Fatalf("expected ErrReadOnly, got %v", err)
	}
}

func TestManagerStreamsOutput(t *testing.T) {
	process := newFakeProcess()
	manager := NewManager(1024, fakeAdapter{process: process})
	s, err := manager.Create(context.Background(), "test", domain.TargetSpec{Kind: "fake"}, domain.PermissionInteractive)
	if err != nil {
		t.Fatal(err)
	}
	_, stream, cancel, err := manager.Subscribe(s.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	if _, err := process.outputW.Write([]byte("output")); err != nil {
		t.Fatal(err)
	}
	select {
	case chunk := <-stream:
		if string(chunk.Data) != "output" {
			t.Fatalf("unexpected output %q", chunk.Data)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for output")
	}
}

func TestManagerLifecycleAndValidation(t *testing.T) {
	process := newFakeProcess()
	manager := NewManager(0, fakeAdapter{process: process}, failingAdapter{})
	manager.RegisterDetector("fake", detectorFunc(func([]byte) (target.StateObservation, bool) {
		return target.StateObservation{State: domain.StateWaitingForInput, Confidence: 0.9}, true
	}))
	if _, err := manager.Create(context.Background(), "bad", domain.TargetSpec{Kind: "unknown"}, domain.PermissionInteractive); err == nil {
		t.Fatal("unknown adapter accepted")
	}
	if _, err := manager.Create(context.Background(), "spawn-error", domain.TargetSpec{Kind: "failing"}, domain.PermissionInteractive); err == nil {
		t.Fatal("spawn error ignored")
	}
	created, err := manager.Create(context.Background(), "named", domain.TargetSpec{Kind: "fake", Args: []string{"one"}, Env: map[string]string{"SECRET": "hidden"}}, domain.PermissionInteractive)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Create(context.Background(), "named", domain.TargetSpec{Kind: "fake"}, domain.PermissionInteractive); err != ErrDuplicate {
		t.Fatalf("duplicate name error = %v", err)
	}
	if got, err := manager.Get("named"); err != nil || got.ID != created.ID || got.Target.Env != nil {
		t.Fatalf("get returned %+v, %v", got, err)
	}
	if len(manager.List()) != 1 {
		t.Fatal("session missing from list")
	}
	if err := manager.Resize(created.ID, 90, 30); err != nil {
		t.Fatal(err)
	}
	if err := manager.Signal(created.ID, target.SignalInterrupt); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Replay("missing", 0); err != ErrNotFound {
		t.Fatalf("missing replay error = %v", err)
	}
	for _, input := range []struct {
		key  string
		data []byte
	}{{"", []byte("x")}, {"key", nil}, {"key", make([]byte, MaxInputBytes+1)}} {
		if err := manager.Input(created.ID, "device", input.key, input.data); err == nil {
			t.Fatalf("invalid input accepted: key=%q len=%d", input.key, len(input.data))
		}
	}
	if _, err := process.outputW.Write([]byte("permission prompt")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		got, _ := manager.Get(created.ID)
		if got.State == domain.StateWaitingForInput {
			break
		}
		time.Sleep(time.Millisecond)
	}
	close(process.done)
	_ = process.outputW.Close()
	deadline = time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		got, _ := manager.Get(created.ID)
		if got.State == domain.StateFinished {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("session did not finish")
}

type detectorFunc func([]byte) (target.StateObservation, bool)

func (f detectorFunc) Detect(data []byte) (target.StateObservation, bool) { return f(data) }

func TestManagerSubscriptionGapAndCancellation(t *testing.T) {
	process := newFakeProcess()
	manager := NewManager(3, fakeAdapter{process: process})
	created, err := manager.Create(context.Background(), "gap", domain.TargetSpec{Kind: "fake"}, domain.PermissionInteractive)
	if err != nil {
		t.Fatal(err)
	}
	_, stream, cancel, err := manager.Subscribe(created.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if _, ok := <-stream; ok {
		t.Fatal("cancel did not close stream")
	}
	_, _ = process.outputW.Write([]byte("abc"))
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		replay, _ := manager.Replay(created.ID, 0)
		if replay.MaxSeq == 1 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	_, _ = process.outputW.Write([]byte("def"))
	deadline = time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		replay, _ := manager.Replay(created.ID, 1)
		if replay.Gap {
			gap, stream, cancel, err := manager.Subscribe(created.ID, 1)
			if err != nil || !gap.Gap || stream != nil || cancel != nil {
				t.Fatalf("unexpected gap subscription: %+v %v", gap, err)
			}
			close(process.done)
			_ = process.outputW.Close()
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("output was not retained")
}

type scriptedProcess struct {
	reader    io.Reader
	writeN    int
	writeErr  error
	waitCode  int
	waitErr   error
	waitBlock chan struct{}
}

func (p *scriptedProcess) Write(data []byte) (int, error) {
	if p.writeN >= 0 && p.writeN < len(data) {
		return p.writeN, p.writeErr
	}
	return len(data), p.writeErr
}
func (p *scriptedProcess) Output() io.Reader {
	if p.reader == nil {
		return bytes.NewReader(nil)
	}
	return p.reader
}
func (p *scriptedProcess) Resize(uint16, uint16) error { return io.ErrUnexpectedEOF }
func (p *scriptedProcess) Signal(target.Signal) error  { return io.ErrUnexpectedEOF }
func (p *scriptedProcess) Wait() (int, error) {
	if p.waitBlock != nil {
		<-p.waitBlock
	}
	return p.waitCode, p.waitErr
}
func (p *scriptedProcess) Close() error { return nil }

type scriptedAdapter struct{ process *scriptedProcess }

func (scriptedAdapter) Kind() string { return "scripted" }
func (a scriptedAdapter) Spawn(context.Context, domain.TargetSpec) (target.Process, error) {
	return a.process, nil
}

type dataErrorReader struct{ sent bool }

func (r *dataErrorReader) Read(buffer []byte) (int, error) {
	if r.sent {
		return 0, io.EOF
	}
	r.sent = true
	return copy(buffer, bytes.Repeat([]byte("x"), 9000)), io.ErrUnexpectedEOF
}

func TestManagerProcessErrorBranches(t *testing.T) {
	process := &scriptedProcess{reader: &dataErrorReader{}, writeN: 0, waitCode: -1, waitErr: io.ErrUnexpectedEOF, waitBlock: make(chan struct{})}
	manager := NewManager(16<<10, scriptedAdapter{process})
	manager.RegisterDetector("scripted", detectorFunc(func([]byte) (target.StateObservation, bool) {
		return target.StateObservation{State: domain.StateIdle, Confidence: 0.1}, true
	}))
	created, err := manager.Create(context.Background(), "errors", domain.TargetSpec{Kind: "scripted"}, domain.PermissionInteractive)
	if err != nil {
		t.Fatal(err)
	}
	rs, _ := manager.Resolve(created.ID)
	rs.mu.Lock()
	blocked := make(chan Chunk)
	rs.subscribers[999] = blocked
	rs.mu.Unlock()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		got, _ := manager.Get(created.ID)
		if got.State == domain.StateError {
			break
		}
		time.Sleep(time.Millisecond)
	}
	close(process.waitBlock)
	if err := manager.Resize(created.ID, 1, 1); err == nil {
		t.Fatal("resize error ignored")
	}
	if err := manager.Signal(created.ID, target.SignalKill); err == nil {
		t.Fatal("signal error ignored")
	}
	if err := manager.Resize("missing", 1, 1); err != ErrNotFound {
		t.Fatalf("missing resize error=%v", err)
	}
	if err := manager.Signal("missing", target.SignalKill); err != ErrNotFound {
		t.Fatalf("missing signal error=%v", err)
	}
	if err := manager.Input(created.ID, "device", "short", []byte("x")); err != io.ErrShortWrite {
		t.Fatalf("short write error=%v", err)
	}
}

func TestManagerInputWriteFailureAndDedupeEviction(t *testing.T) {
	failed := &scriptedProcess{reader: bytes.NewReader(nil), writeN: 0, writeErr: io.ErrClosedPipe}
	manager := NewManager(32, scriptedAdapter{failed})
	created, _ := manager.Create(context.Background(), "failed", domain.TargetSpec{Kind: "scripted"}, domain.PermissionInteractive)
	if err := manager.Input(created.ID, "device", "write", []byte("x")); err != io.ErrClosedPipe {
		t.Fatalf("write error=%v", err)
	}

	process := newFakeProcess()
	manager = NewManager(32, fakeAdapter{process})
	created, _ = manager.Create(context.Background(), "dedupe", domain.TargetSpec{Kind: "fake"}, domain.PermissionInteractive)
	for index := 0; index < 1025; index++ {
		key := fmt.Sprintf("key-%d", index)
		if err := manager.Input(created.ID, "device", key, []byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	if err := manager.Input(created.ID, "device", "key-0", []byte("x")); err != nil {
		t.Fatal(err)
	}
	process.mu.Lock()
	length := process.writes.Len()
	process.mu.Unlock()
	if length != 1026 {
		t.Fatalf("evicted idempotency key was not accepted again: writes=%d", length)
	}
	close(process.done)
	_ = process.outputW.Close()
}
