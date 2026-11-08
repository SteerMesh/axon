# Deploying axon-relay

This directory packages `axon-relay` for **self-hosted, single-operator or
small-team deployment** — a solo relay you or your team run on a server or
VPS you control. It is not a managed, multi-tenant service: the relay's own
credential model (`AXON_RELAY_MATE_KEYS`, a hand-provisioned flat allowlist
of mate public keys, no accounts/tenancy) assumes one operator per relay.
There is no Kubernetes manifest or Helm chart here, and none is planned for
this topology — see "What's deliberately not here" below.

This is about `axon-relay` only. `mesh-axon` (the mate) already has its own
install story for a personal workstation — a per-user LaunchAgent on macOS
or a per-user systemd unit on Linux, installed via `mesh-axon install` (see
`internal/service/install.go`). That's a different lifecycle (a background
agent tied to a desktop login session) from the relay, which runs
unattended on a server with no logged-in session, and this directory
doesn't touch or extend it.

Two deployment paths are documented:

- [Docker Compose](#docker-compose) — simplest path, good default for most
  self-hosters.
- [systemd](#systemd) — for running the binary directly on a Linux host
  without a container runtime.

Both end up running the same binary with the same environment variables; pick
whichever fits how you already manage the host.

## Before either path: get a mate key

`axon-relay` refuses to start without at least one entry in
`AXON_RELAY_MATE_KEYS`. That value comes from the *mate*, not the relay —
see `docs/GETTING_STARTED.md`, "Step 1 — get your mate's identity" for the
full explanation of what a mate identity is and why the relay needs it.
Short version:

```bash
./bin/mesh-axon identity
```

prints a line like:

```text
AXON_RELAY_MATE_KEYS fragment: laptop=AbCdEf0123456789...==
```

Copy that fragment into whichever config file your chosen path below uses
(`.env` for Compose, `/etc/axon-relay/env` for systemd). One fragment per
mate that should be allowed to connect, comma-separated.

See `docs/GETTING_STARTED.md` for the other optional environment variables
(VAPID keys for Web Push, rate-limit tunables, origins) — this README only
covers what's specific to packaging the relay for deployment.

## Docker Compose

Files: [`Dockerfile`](./Dockerfile), [`docker-compose.yml`](./docker-compose.yml),
[`.env.example`](./.env.example).

1. From this directory, copy the env template and fill it in:

   ```bash
   cp .env.example .env
   $EDITOR .env   # set AXON_RELAY_MATE_KEYS at minimum
   ```

2. Build and start:

   ```bash
   docker compose up -d --build
   ```

   This builds the image from the repo root (the Compose file's `build.context`
   points two directories up) using the multi-stage `Dockerfile` in this
   directory, then starts the container.

   If you'd rather build once and push to a registry instead of building on
   every host that runs the relay, replace the `build:` block in
   `docker-compose.yml` with `image: your-registry/axon-relay:tag` and do the
   build/push step separately (`docker build -f deploy/axon-relay/Dockerfile
   -t your-registry/axon-relay:tag . && docker push ...`). That's a
   reasonable next step for a small team but isn't automated here — see
   "Possible follow-ups" below.

3. Check it's up:

   ```bash
   curl -fsS http://localhost:8080/healthz
   curl -fsS http://127.0.0.1:9090/metrics
   ```

   The second one only works from the same host by design — see the port
   mapping comment in `docker-compose.yml`. `axon-relay`'s own default
   (`AXON_RELAY_METRICS_ADDR=127.0.0.1:9090`, when run outside a container)
   is to keep metrics host-local; the Compose file reproduces that same
   effective exposure (metrics reachable only from the Docker host's own
   loopback) even though the *container-internal* bind has to be `0.0.0.0`
   for Docker's port forwarding to work at all. Don't change the published
   port's host-side binding to `0.0.0.0` unless you're intentionally
   exposing metrics beyond the host (e.g. to a Prometheus server on another
   machine) — if you do, put it behind your own network controls.

4. State: the push-subscription SQLite store (`axon-relay.db`) lives in the
   named volume `axon-relay-data`, mounted at `/var/lib/axon-relay` in the
   container. It survives `docker compose down` / `up` and `docker compose
   restart`. It's only created once you've configured VAPID keys to enable
   Web Push (see `docs/GETTING_STARTED.md`, Step 7) — opening the file is
   skipped entirely otherwise.

5. Update/restart:

   ```bash
   git pull
   docker compose up -d --build   # rebuilds the image, recreates the container
   # or, after a plain restart with no code change:
   docker compose restart axon-relay
   ```

6. Logs:

   ```bash
   docker compose logs -f axon-relay
   ```

## systemd

File: [`axon-relay.service`](./axon-relay.service).

This is a **system**-level unit (installed under `/etc/systemd/system/`,
enabled with plain `systemctl`, not `systemctl --user`) — appropriate for a
server with no logged-in session, unlike the mate's per-user service. It
runs as a dedicated, unprivileged system user rather than root.

1. Build the binary (on the target host, or copy a build over):

   ```bash
   make build   # from the repo root; produces bin/axon-relay
   ```

2. Create the dedicated system user (one-time; this does **not** exist by
   default, you need to create it):

   ```bash
   sudo useradd --system --no-create-home --shell /usr/sbin/nologin axon-relay
   ```

3. Install the binary to the path the unit file expects
   (`/usr/local/bin/axon-relay`):

   ```bash
   sudo install -m 0755 bin/axon-relay /usr/local/bin/axon-relay
   ```

4. Create the state directory (for the push-subscription SQLite store) and
   the environment file, owned appropriately:

   ```bash
   sudo mkdir -p /var/lib/axon-relay /etc/axon-relay
   sudo chown axon-relay:axon-relay /var/lib/axon-relay
   sudo touch /etc/axon-relay/env
   sudo chmod 640 /etc/axon-relay/env
   sudo chown root:axon-relay /etc/axon-relay/env
   ```

5. Populate `/etc/axon-relay/env` (at minimum):

   ```bash
   AXON_RELAY_MATE_KEYS=laptop=AbCdEf0123456789...==
   ```

   Add any of the optional variables from `docs/GETTING_STARTED.md` on
   their own lines the same way (`AXON_RELAY_VAPID_PUBLIC_KEY`,
   `AXON_RELAY_ORIGINS`, the rate-limit tunables, etc.). `AXON_RELAY_ADDR`
   and `AXON_RELAY_METRICS_ADDR` can be left unset here — the unit's
   `WorkingDirectory=/var/lib/axon-relay` already makes the relay's default
   relative `AXON_RELAY_DB_PATH` (`axon-relay.db`) resolve to
   `/var/lib/axon-relay/axon-relay.db`, owned by the `axon-relay` user.

6. Install and enable the unit:

   ```bash
   sudo cp deploy/axon-relay/axon-relay.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now axon-relay
   ```

7. Check it's up:

   ```bash
   sudo systemctl status axon-relay
   curl -fsS http://localhost:8080/healthz
   curl -fsS http://127.0.0.1:9090/metrics
   ```

8. Update/restart:

   ```bash
   sudo systemctl stop axon-relay
   sudo install -m 0755 bin/axon-relay /usr/local/bin/axon-relay   # new build
   sudo systemctl start axon-relay
   # or, for a config-only change (edited /etc/axon-relay/env):
   sudo systemctl restart axon-relay
   ```

9. Logs:

   ```bash
   sudo journalctl -u axon-relay -f
   ```

## What's deliberately not here

Per the architecture review for this packaging work:

- **No Kubernetes manifests or Helm chart.** Ruled out by the self-hosted,
  per-operator topology (see the credential model note above), not a
  default-to-common-tooling choice — there's no multi-tenancy or
  autoscaling need this would be solving for.
- **No CI/CD pipeline changes.** This directory is the deployment
  artifacts (Dockerfile, Compose file, systemd unit); it doesn't include an
  automated build/push workflow. An automated image build/publish step on
  tag or merge would be a reasonable follow-up once there's an actual
  release process for this repo (see `docs/GETTING_STARTED.md`'s note that
  `SteerMesh/axon` has no tagged release yet).
- **No alerting rules or dashboards.** Explicitly deferred in the original
  design note for this work — meaningful alert thresholds need real
  production traffic patterns first, which don't exist yet. `/metrics`
  (Prometheus) is exposed and ready to scrape in both deployment paths
  above; wiring it into an actual Prometheus/Grafana/alerting stack is left
  to the operator.
