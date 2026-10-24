//go:build unix

package target

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"

	"github.com/SteerMesh/axon/internal/domain"
	"github.com/creack/pty"
)

type ShellAdapter struct {
	kind string
	path string
}

func NewShellAdapter(kind, path string) *ShellAdapter {
	return &ShellAdapter{kind: kind, path: path}
}

func (a *ShellAdapter) Kind() string { return a.kind }

func (a *ShellAdapter) Spawn(ctx context.Context, spec domain.TargetSpec) (Process, error) {
	args := spec.Args
	if len(args) == 0 {
		args = []string{"-l"}
	}
	return spawnPTY(ctx, a.kind, a.path, args, spec)
}

func spawnPTY(ctx context.Context, kind, path string, args []string, spec domain.TargetSpec) (Process, error) {
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Dir = spec.Cwd
	cmd.Env = append([]string(nil), os.Environ()...)
	for key, value := range spec.Env {
		cmd.Env = append(cmd.Env, key+"="+value)
	}
	cols, rows := spec.Cols, spec.Rows
	if cols == 0 {
		cols = 80
	}
	if rows == 0 {
		rows = 24
	}
	file, err := pty.StartWithSize(cmd, &pty.Winsize{Cols: cols, Rows: rows})
	if err != nil {
		return nil, fmt.Errorf("start %s PTY: %w", kind, err)
	}
	return &ptyProcess{cmd: cmd, file: file}, nil
}

type ptyProcess struct {
	cmd  *exec.Cmd
	file *os.File
}

func (p *ptyProcess) Write(data []byte) (int, error) { return p.file.Write(data) }
func (p *ptyProcess) Close() error                   { return p.file.Close() }
func (p *ptyProcess) Output() io.Reader              { return p.file }

func (p *ptyProcess) Resize(cols, rows uint16) error {
	if cols == 0 || rows == 0 {
		return fmt.Errorf("terminal dimensions must be positive")
	}
	return pty.Setsize(p.file, &pty.Winsize{Cols: cols, Rows: rows})
}

func (p *ptyProcess) Signal(signal Signal) error {
	if p.cmd.Process == nil {
		return fmt.Errorf("process has not started")
	}
	var sig syscall.Signal
	switch signal {
	case SignalInterrupt:
		sig = syscall.SIGINT
	case SignalTerminate:
		sig = syscall.SIGTERM
	case SignalKill:
		sig = syscall.SIGKILL
	default:
		return fmt.Errorf("unsupported signal %q", signal)
	}
	return syscall.Kill(-p.cmd.Process.Pid, sig)
}

func (p *ptyProcess) Wait() (int, error) {
	err := p.cmd.Wait()
	if p.cmd.ProcessState == nil {
		return -1, err
	}
	return p.cmd.ProcessState.ExitCode(), err
}
