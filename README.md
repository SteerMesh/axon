# Mesh Axon

Mesh Axon securely connects mobile devices to Mesh-managed agent sessions. The
default remote entry point is `mesh chat`; raw terminal sessions are an explicit
diagnostic option. The host-side Axon Agent owns PTYs, Axon Relay forwards opaque
end-to-end encrypted frames, and the Axon web client provides a mobile-first
terminal and prompt composer.

## Status

Axon is under active development. The local PTY and protocol foundations are
usable, and the relay-to-PWA MVP is implemented. Remote and mobile surfaces
remain pre-release; see `docs/IMPLEMENTATION_STATUS.md` for the production
hardening backlog.

## Components

| Component  | Location          | Purpose                                      |
|------------|-------------------|----------------------------------------------|
| Agent      | `cmd/mesh-axon`   | Own sessions and expose the local IPC socket |
| Relay      | `cmd/axon-relay`  | Route opaque encrypted frames                |
| Web client | `web/`            | Mobile PWA terminal and prompt composer      |
| Protocol   | `pkg/protocol/`   | Versioned wire messages                      |

## Development

```bash
make test
make build
```

Start the local agent:

```bash
./bin/mesh-axon serve
./bin/mesh-axon run --name demo
./bin/mesh-axon sessions
```

The default command starts `mesh chat`. To request a specific runtime or open a
raw diagnostic shell:

```bash
./bin/mesh-axon run --name codex-demo mesh -- --target codex
./bin/mesh-axon run zsh --name shell-debug
```

After pairing, the web client lists every live session owned by the Axon Agent.
Select a session to attach to its retained output and continue interacting with
its process. The **New Mesh chat** form discovers installed Mesh workspaces and
offers the runtimes supported by `mesh chat --target`.

Axon cannot adopt an arbitrary process started in another terminal because it
does not own that process's PTY. Start the process through Axon, or use the
explicit `tmux-attach` target for an independently persistent terminal session.

## Security

Axon is not approved for employer-managed machines unless the employer's
security team has explicitly authorized its use. Report vulnerabilities using
the private security-reporting flow on GitHub rather than a public issue.
