//go:build unix

package target

import (
	"bufio"
	"context"
	"io"
	"os/exec"
	"strings"
	"syscall"
	"testing"

	"github.com/SteerMesh/axon/internal/domain"
)

func TestSSHAllowlist(t *testing.T) {
	validate := SSHHostAllowlist([]string{"dev.example"})
	if err := validate(domain.TargetSpec{Args: []string{"dev.example"}}); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"prod.example"}, {"-oProxyCommand=bad"}, nil} {
		if err := validate(domain.TargetSpec{Args: args}); err == nil {
			t.Fatalf("accepted unsafe args %v", args)
		}
	}
}

func TestDockerAllowlist(t *testing.T) {
	validate := DockerContainerAllowlist([]string{"worker"})
	if err := validate(domain.TargetSpec{Args: []string{"worker"}}); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{nil, {"-privileged"}, {"database"}} {
		if err := validate(domain.TargetSpec{Args: args}); err == nil {
			t.Fatalf("accepted unsafe args %v", args)
		}
	}
}

func TestCommandAndShellAdaptersRunInPTY(t *testing.T) {
	command := NewCommandAdapter("command", "/bin/sh", "-c")
	if command.Kind() != "command" {
		t.Fatalf("unexpected kind %q", command.Kind())
	}
	process, err := command.Spawn(context.Background(), domain.TargetSpec{Args: []string{"printf command-output"}, Cols: 40, Rows: 10})
	if err != nil {
		t.Fatal(err)
	}
	output, err := io.ReadAll(process.Output())
	if err != nil {
		t.Fatal(err)
	}
	if code, err := process.Wait(); err != nil || code != 0 || !strings.Contains(string(output), "command-output") {
		t.Fatalf("command result code=%d output=%q err=%v", code, output, err)
	}

	shell := NewShellAdapter("shell", "/bin/sh")
	if shell.Kind() != "shell" {
		t.Fatalf("unexpected kind %q", shell.Kind())
	}
	process, err = shell.Spawn(context.Background(), domain.TargetSpec{Args: []string{"-c", "printf shell-output"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Resize(120, 40); err != nil {
		t.Fatal(err)
	}
	if err := process.Resize(0, 40); err == nil {
		t.Fatal("zero-width resize was accepted")
	}
	output, err = io.ReadAll(process.Output())
	if err != nil {
		t.Fatal(err)
	}
	if code, err := process.Wait(); err != nil || code != 0 || !strings.Contains(string(output), "shell-output") {
		t.Fatalf("shell result code=%d output=%q err=%v", code, output, err)
	}
}

func TestCommandAdapterValidationAndSignalErrors(t *testing.T) {
	adapter := NewCommandAdapter("blocked", "/bin/sh").WithValidator(func(domain.TargetSpec) error {
		return io.ErrUnexpectedEOF
	})
	if _, err := adapter.Spawn(context.Background(), domain.TargetSpec{}); err == nil {
		t.Fatal("validator error was ignored")
	}
	if _, err := NewCommandAdapter("missing", "/definitely/not/a/binary").Spawn(context.Background(), domain.TargetSpec{}); err == nil {
		t.Fatal("missing executable was started")
	}
	process, err := NewCommandAdapter("sleep", "/bin/sh", "-c").Spawn(context.Background(), domain.TargetSpec{Args: []string{"sleep 10"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Signal(Signal("invalid")); err == nil {
		t.Fatal("invalid signal was accepted")
	}
	if err := process.Signal(SignalTerminate); err != nil {
		t.Fatal(err)
	}
	_, _ = process.Wait()
}

func TestCommandAdapterTrustedEnvironment(t *testing.T) {
	adapter := NewCommandAdapter("env", "/bin/sh", "-c").WithEnv("AXON_TEST_MANAGED", "trusted")
	process, err := adapter.Spawn(context.Background(), domain.TargetSpec{
		Args: []string{"printf %s \"$AXON_TEST_MANAGED\""},
		Env:  map[string]string{"AXON_TEST_MANAGED": "untrusted"},
	})
	if err != nil {
		t.Fatal(err)
	}
	output, err := io.ReadAll(process.Output())
	if err != nil {
		t.Fatal(err)
	}
	if code, err := process.Wait(); err != nil || code != 0 || !strings.Contains(string(output), "trusted") {
		t.Fatalf("command result code=%d output=%q err=%v", code, output, err)
	}
}

func TestPTYWriteAndClose(t *testing.T) {
	process, err := NewCommandAdapter("cat", "/bin/cat").Spawn(context.Background(), domain.TargetSpec{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := process.Write([]byte("echoed\n")); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(process.Output()).ReadString('\n')
	if err != nil || !strings.Contains(line, "echoed") {
		t.Fatalf("line=%q err=%v", line, err)
	}
	if err := process.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestPTYProcessSignals(t *testing.T) {
	for _, signal := range []Signal{SignalInterrupt, SignalKill} {
		process, err := NewCommandAdapter("sleep", "/bin/sh", "-c").Spawn(context.Background(), domain.TargetSpec{Args: []string{"sleep 10"}})
		if err != nil {
			t.Fatal(err)
		}
		if err := process.Signal(signal); err != nil {
			t.Fatalf("signal %s: %v", signal, err)
		}
		_, _ = process.Wait()
	}
}

func TestUnstartedPTYProcessErrors(t *testing.T) {
	process := &ptyProcess{cmd: &exec.Cmd{}}
	if err := process.Signal(SignalInterrupt); err == nil {
		t.Fatal("unstarted process accepted a signal")
	}
	if code, err := process.Wait(); code != -1 || err == nil {
		t.Fatalf("wait result code=%d err=%v", code, err)
	}
}

type fixedReader struct {
	data []byte
	err  error
}

func (r fixedReader) Read(buffer []byte) (int, error) {
	return copy(buffer, r.data), r.err
}

func TestPTYReaderNormalizesLinuxEIO(t *testing.T) {
	reader := ptyReader{Reader: fixedReader{data: []byte("done"), err: syscall.EIO}}
	buffer := make([]byte, 8)
	n, err := reader.Read(buffer)
	if n != 4 || err != io.EOF || string(buffer[:n]) != "done" {
		t.Fatalf("n=%d err=%v data=%q", n, err, buffer[:n])
	}
	reader = ptyReader{Reader: fixedReader{err: io.ErrUnexpectedEOF}}
	if _, err := reader.Read(buffer); err != io.ErrUnexpectedEOF {
		t.Fatalf("unexpected error normalization: %v", err)
	}
}
