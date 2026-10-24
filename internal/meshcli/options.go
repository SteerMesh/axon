package meshcli

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"slices"
	"sort"
)

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type Options struct {
	Workspaces []string `json:"workspaces"`
	Targets    []string `json:"targets"`
}

func Discover(ctx context.Context, executable string) (Options, error) {
	output, err := exec.CommandContext(ctx, executable, "workspace", "list", "--json").Output()
	if err != nil {
		return Options{}, fmt.Errorf("list Mesh workspaces: %w", err)
	}
	workspaces, err := parseWorkspaces(output)
	if err != nil {
		return Options{}, err
	}
	return Options{
		Workspaces: workspaces,
		Targets:    []string{"kiro", "cursor", "codex", "api", "coda", "orchestrator"},
	}, nil
}

func (o Options) BuildArgs(workspace, target string) ([]string, error) {
	var args []string
	if workspace != "" {
		if !identifierPattern.MatchString(workspace) || !slices.Contains(o.Workspaces, workspace) {
			return nil, fmt.Errorf("Mesh workspace %q is not available", workspace)
		}
		args = append(args, "--ws", workspace)
	}
	if target != "" {
		if !slices.Contains(o.Targets, target) {
			return nil, fmt.Errorf("Mesh target %q is not supported", target)
		}
		args = append(args, "--target", target)
	}
	return args, nil
}

func parseWorkspaces(data []byte) ([]string, error) {
	var entries []struct {
		Workspace struct {
			Name string `json:"name"`
		} `json:"Workspace"`
	}
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("decode Mesh workspaces: %w", err)
	}
	result := make([]string, 0, len(entries))
	for _, entry := range entries {
		if identifierPattern.MatchString(entry.Workspace.Name) {
			result = append(result, entry.Workspace.Name)
		}
	}
	sort.Strings(result)
	return result, nil
}
