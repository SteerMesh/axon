//go:build unix

package target

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/SteerMesh/axon/internal/domain"
)

type CommandAdapter struct {
	kind       string
	executable string
	prefixArgs []string
	env        map[string]string
	validator  func(domain.TargetSpec) error
}

// WithEnv adds a trusted environment variable to every process spawned by
// this adapter. Adapter values take precedence over caller-supplied values.
func (a *CommandAdapter) WithEnv(key, value string) *CommandAdapter {
	if a.env == nil {
		a.env = make(map[string]string)
	}
	a.env[key] = value
	return a
}

func NewCommandAdapter(kind, executable string, prefixArgs ...string) *CommandAdapter {
	return &CommandAdapter{kind: kind, executable: executable, prefixArgs: append([]string(nil), prefixArgs...)}
}

func (a *CommandAdapter) WithValidator(validator func(domain.TargetSpec) error) *CommandAdapter {
	a.validator = validator
	return a
}

func (a *CommandAdapter) Kind() string { return a.kind }

func (a *CommandAdapter) Spawn(ctx context.Context, spec domain.TargetSpec) (Process, error) {
	if a.validator != nil {
		if err := a.validator(spec); err != nil {
			return nil, err
		}
	}
	if len(a.env) > 0 {
		env := make(map[string]string, len(spec.Env)+len(a.env))
		for key, value := range spec.Env {
			env[key] = value
		}
		for key, value := range a.env {
			env[key] = value
		}
		spec.Env = env
	}
	args := append(append([]string(nil), a.prefixArgs...), spec.Args...)
	return spawnPTY(ctx, a.kind, a.executable, args, spec)
}

func SSHHostAllowlist(hosts []string) func(domain.TargetSpec) error {
	allowed := append([]string(nil), hosts...)
	return func(spec domain.TargetSpec) error {
		if len(spec.Args) == 0 {
			return fmt.Errorf("ssh target requires a host")
		}
		host := spec.Args[0]
		if strings.HasPrefix(host, "-") || !slices.Contains(allowed, host) {
			return fmt.Errorf("ssh host %q is not allowed", host)
		}
		return nil
	}
}

func DockerContainerAllowlist(containers []string) func(domain.TargetSpec) error {
	allowed := append([]string(nil), containers...)
	return func(spec domain.TargetSpec) error {
		if len(spec.Args) == 0 || strings.HasPrefix(spec.Args[0], "-") || !slices.Contains(allowed, spec.Args[0]) {
			return fmt.Errorf("docker container is not allowed")
		}
		return nil
	}
}
