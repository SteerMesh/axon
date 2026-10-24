package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/SteerMesh/axon/internal/detector"
	"github.com/SteerMesh/axon/internal/domain"
	"github.com/SteerMesh/axon/internal/ipc"
	"github.com/SteerMesh/axon/internal/meshcli"
	"github.com/SteerMesh/axon/internal/remote"
	"github.com/SteerMesh/axon/internal/security"
	serviceinstaller "github.com/SteerMesh/axon/internal/service"
	"github.com/SteerMesh/axon/internal/session"
	"github.com/SteerMesh/axon/internal/store"
	"github.com/SteerMesh/axon/internal/target"
	"github.com/SteerMesh/axon/internal/templates"
	"github.com/mdp/qrterminal/v3"
	"github.com/oklog/ulid/v2"
	"github.com/spf13/cobra"
	"rsc.io/qr"
)

var socketPath string

func main() {
	path, err := ipc.DefaultSocketPath()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	root := newRoot(path)
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newRoot(defaultSocket string) *cobra.Command {
	root := &cobra.Command{
		Use:           "mesh-axon",
		Short:         "Secure remote access to Mesh-managed sessions",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&socketPath, "socket", defaultSocket, "Axon Agent Unix socket")
	root.AddCommand(newServeCommand(), newRunCommand(), newSessionsCommand(), newAttachCommand(), newSignalCommand(), newStatusCommand(), newServiceCommand(), newPairCommand(), newDevicesCommand())
	return root
}

func newServeCommand() *cobra.Command {
	var sshHosts, dockerContainers []string
	var relayURL, relayToken, mateID, dataDir string
	command := &cobra.Command{
		Use:   "serve",
		Short: "Run the Axon Agent",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if dataDir == "" {
				home, err := os.UserHomeDir()
				if err != nil {
					return err
				}
				dataDir = filepath.Join(home, ".mesh", "axon")
			}
			identity, err := security.LoadOrCreateIdentity(filepath.Join(dataDir, "identity.json"))
			if err != nil {
				return err
			}
			if mateID == "" {
				mateID = security.IdentityID(identity)
			}
			persistent, err := store.Open(filepath.Join(dataDir, "axon.db"))
			if err != nil {
				return err
			}
			defer persistent.Close()
			manager := session.NewManager(
				session.DefaultScrollbackBytes,
				target.NewCommandAdapter("mesh", "mesh", "chat").WithEnv("MESH_AXON_MANAGED", "1"),
				target.NewShellAdapter("zsh", "/bin/zsh"),
				target.NewShellAdapter("bash", "/bin/bash"),
				target.NewCommandAdapter("claude", "claude"),
				target.NewCommandAdapter("kiro-cli", "kiro-cli"),
				target.NewCommandAdapter("ssh", "ssh").WithValidator(target.SSHHostAllowlist(sshHosts)),
				target.NewCommandAdapter("docker-exec", "docker", "exec", "-it").WithValidator(target.DockerContainerAllowlist(dockerContainers)),
				target.NewCommandAdapter("tmux-attach", "tmux", "attach-session", "-t"),
			)
			manager.RegisterDetector("zsh", detector.OSC133{})
			manager.RegisterDetector("bash", detector.OSC133{})
			manager.RegisterDetector("claude", detector.NewPromptHeuristic("claude.prompt", `allow this action`, `do you want to proceed`, `waiting for input`))
			manager.RegisterDetector("kiro-cli", detector.NewPromptHeuristic("kiro.prompt", `allow this action`, `do you want to proceed`, `waiting for input`))
			pairing := security.NewPairingManager(mateID, relayURL, identity)
			server, err := ipc.ListenWithOptions(manager, socketPath, ipc.Options{Pairing: pairing, Store: persistent})
			if err != nil {
				return err
			}
			defer server.Close()
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			if relayURL != "" {
				if relayToken == "" {
					return fmt.Errorf("--relay-token or AXON_RELAY_TOKEN is required with --relay-url")
				}
				dispatcher := remote.NewDispatcher(manager, persistent)
				meshOptions, optionsErr := meshcli.Discover(ctx, "mesh")
				if optionsErr != nil {
					fmt.Fprintf(os.Stderr, "warning: %v\n", optionsErr)
				}
				dispatcher.WithMeshOptions(meshOptions)
				catalog := templates.DefaultCatalog()
				templatePath := filepath.Join(dataDir, "templates.yaml")
				if _, statErr := os.Stat(templatePath); statErr == nil {
					configured, loadErr := templates.Load(templatePath)
					if loadErr != nil {
						return loadErr
					}
					catalog = catalog.Merge(configured)
				} else if !errors.Is(statErr, os.ErrNotExist) {
					return statErr
				}
				dispatcher.WithTemplates(catalog)
				endpoint := remote.NewEndpoint(mateID, identity, persistent, dispatcher).WithPairing(pairing)
				connector := remote.NewConnector(relayURL, relayToken, mateID, endpoint)
				go func() {
					_ = connector.Run(ctx)
				}()
			}
			fmt.Printf("Axon Agent %s listening on %s\n", mateID, socketPath)
			<-ctx.Done()
			return nil
		},
	}
	command.Flags().StringSliceVar(&sshHosts, "ssh-host", nil, "Allowed SSH host (repeatable)")
	command.Flags().StringSliceVar(&dockerContainers, "docker-container", nil, "Allowed Docker container (repeatable)")
	command.Flags().StringVar(&relayURL, "relay-url", os.Getenv("AXON_RELAY_URL"), "Axon Relay URL")
	command.Flags().StringVar(&relayToken, "relay-token", os.Getenv("AXON_RELAY_TOKEN"), "Axon Relay access token")
	command.Flags().StringVar(&mateID, "mate-id", "", "Stable host identity (derived from the signing key by default)")
	command.Flags().StringVar(&dataDir, "data-dir", "", "Agent state directory (default ~/.mesh/axon)")
	return command
}

func newRunCommand() *cobra.Command {
	var name, cwd, permission string
	var attachCreated bool
	command := &cobra.Command{
		Use:   "run [mesh|zsh|bash|target] [args...]",
		Short: "Create a managed PTY session",
		RunE: func(cmd *cobra.Command, args []string) error {
			perm := domain.Permission(permission)
			switch perm {
			case domain.PermissionInteractive, domain.PermissionReadOnly, domain.PermissionConfirmInput:
			default:
				return fmt.Errorf("invalid permission %q", permission)
			}
			targetKind := "mesh"
			var targetArgs []string
			if len(args) > 0 {
				targetKind = args[0]
				targetArgs = args[1:]
			}
			params := ipc.CreateParams{
				Name: name,
				Target: domain.TargetSpec{
					Kind: targetKind,
					Args: targetArgs,
					Cwd:  cwd,
				},
				Permission: perm,
			}
			var created domain.Session
			if err := ipc.NewClient(socketPath).Call("session.create", params, &created); err != nil {
				return agentUnavailable(err)
			}
			if attachCreated {
				return attach(socketPath, created.ID, 0)
			}
			fmt.Printf("%s\t%s\t%s\n", created.ID, created.Name, created.State)
			return nil
		},
	}
	command.Flags().StringVar(&name, "name", "", "Unique session name")
	command.Flags().StringVar(&cwd, "cwd", "", "Initial working directory")
	command.Flags().StringVar(&permission, "permission", string(domain.PermissionInteractive), "interactive, read_only, or approve_to_type")
	command.Flags().BoolVar(&attachCreated, "attach", false, "Attach this terminal after creating the session")
	return command
}

func newSessionsCommand() *cobra.Command {
	var outputJSON bool
	command := &cobra.Command{
		Use:     "sessions",
		Aliases: []string{"ls"},
		Short:   "List managed sessions",
		RunE: func(cmd *cobra.Command, _ []string) error {
			var sessions []domain.Session
			if err := ipc.NewClient(socketPath).Call("sessions.list", nil, &sessions); err != nil {
				return agentUnavailable(err)
			}
			if outputJSON {
				return json.NewEncoder(os.Stdout).Encode(sessions)
			}
			fmt.Println("ID\tNAME\tTARGET\tSTATE")
			for _, managed := range sessions {
				fmt.Printf("%s\t%s\t%s\t%s\n", managed.ID, managed.Name, managed.Target.Kind, managed.State)
			}
			return nil
		},
	}
	command.Flags().BoolVar(&outputJSON, "json", false, "Emit JSON")
	return command
}

func newAttachCommand() *cobra.Command {
	var from uint64
	command := &cobra.Command{
		Use:   "attach <session>",
		Short: "Attach this terminal to a session",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return attach(socketPath, args[0], from)
		},
	}
	command.Flags().Uint64Var(&from, "from", 0, "Replay from output sequence")
	return command
}

func newSignalCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "signal <session> <INT|TERM|KILL>",
		Short: "Send a signal to a session",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			sig := strings.ToUpper(args[1])
			if sig != "INT" && sig != "TERM" && sig != "KILL" {
				return fmt.Errorf("unsupported signal %q", args[1])
			}
			return ipc.NewClient(socketPath).Call("session.signal", ipc.SignalParams{SessionID: args[0], Signal: sig}, nil)
		},
	}
}

func newStatusCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Check the local Axon Agent",
		RunE: func(cmd *cobra.Command, _ []string) error {
			var result map[string]string
			if err := ipc.NewClient(socketPath).Call("health", nil, &result); err != nil {
				return agentUnavailable(err)
			}
			fmt.Println(result["status"])
			return nil
		},
	}
}

func newServiceCommand() *cobra.Command {
	serviceCommand := &cobra.Command{Use: "service", Short: "Manage the Axon Agent service"}
	serviceCommand.AddCommand(&cobra.Command{
		Use:   "install",
		Short: "Install a per-user launchd or systemd service",
		RunE: func(cmd *cobra.Command, _ []string) error {
			executable, err := os.Executable()
			if err != nil {
				return err
			}
			executable, err = filepath.EvalSymlinks(executable)
			if err != nil {
				return err
			}
			home, err := os.UserHomeDir()
			if err != nil {
				return err
			}
			path, err := serviceinstaller.Install(executable, home)
			if err != nil {
				return err
			}
			fmt.Printf("Installed %s\n", path)
			if runtime.GOOS == "darwin" {
				return exec.Command("launchctl", "bootstrap", "gui/"+strconv.Itoa(os.Getuid()), path).Run()
			}
			return exec.Command("systemctl", "--user", "enable", "--now", "mesh-axon.service").Run()
		},
	})
	return serviceCommand
}

func newPairCommand() *cobra.Command {
	var ttl time.Duration
	command := &cobra.Command{
		Use:   "pair",
		Short: "Create a one-time mobile pairing code",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if ttl < time.Second || ttl > time.Hour {
				return fmt.Errorf("pairing TTL must be between 1s and 1h")
			}
			var bundle security.PairingBundle
			if err := ipc.NewClient(socketPath).Call("pairing.issue", ipc.PairingIssueParams{TTLSeconds: int64(ttl / time.Second)}, &bundle); err != nil {
				return agentUnavailable(err)
			}
			payload, err := bundle.QRPayload()
			if err != nil {
				return err
			}
			qrterminal.GenerateHalfBlock(payload, qr.M, os.Stdout)
			fmt.Printf("\nExpires: %s\nPairing payload: %s\n", bundle.ExpiresAt.Format(time.RFC3339), payload)
			return nil
		},
	}
	command.Flags().DurationVar(&ttl, "ttl", 5*time.Minute, "Pairing code lifetime")
	return command
}

func newDevicesCommand() *cobra.Command {
	devices := &cobra.Command{Use: "devices", Short: "Manage paired devices"}
	devices.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List paired devices",
		RunE: func(cmd *cobra.Command, _ []string) error {
			var result ipc.DeviceListResult
			if err := ipc.NewClient(socketPath).Call("devices.list", nil, &result); err != nil {
				return agentUnavailable(err)
			}
			fmt.Println("ID\tROLE\tPAIRED\tSTATUS")
			for _, device := range result.Devices {
				status := "active"
				if device.RevokedAt != nil {
					status = "revoked"
				}
				fmt.Printf("%s\t%s\t%s\t%s\n", device.Record.DeviceID, device.Role, device.Record.PairedAt.Format(time.RFC3339), status)
			}
			return nil
		},
	})
	devices.AddCommand(&cobra.Command{
		Use:   "revoke <device-id>",
		Short: "Immediately revoke a paired device",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := ipc.NewClient(socketPath).Call("devices.revoke", ipc.DeviceRevokeParams{DeviceID: args[0]}, nil); err != nil {
				return agentUnavailable(err)
			}
			fmt.Printf("Revoked %s\n", args[0])
			return nil
		},
	})
	return devices
}

func agentUnavailable(err error) error {
	var opErr *os.PathError
	if errors.As(err, &opErr) || strings.Contains(err.Error(), "connect") {
		return fmt.Errorf("Axon Agent is unavailable; start it with 'mesh-axon serve': %w", err)
	}
	return err
}

func inputKey() string { return ulid.Make().String() }
