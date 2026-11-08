# syntax=docker/dockerfile:1

# axon-relay container image.
#
# Build stage compiles the relay binary; runtime stage ships only that
# binary on a minimal base. axon-relay is CGO-free (its sqlite driver is
# modernc.org/sqlite, a pure-Go implementation -- see
# internal/relay/subscriptions.go), so static linking needs nothing from
# the build environment's libc.
#
# Runtime base is gcr.io/distroless/static, not bare `scratch`: when Web
# Push is enabled (AXON_RELAY_VAPID_PUBLIC_KEY/AXON_RELAY_VAPID_PRIVATE_KEY
# both set), the relay dials out over HTTPS to whatever push service each
# browser subscription names (FCM for Chromium-based browsers, Mozilla's
# autopush for Firefox, etc. -- see webpush.SendNotificationWithContext in
# internal/relay/hub.go). That requires a CA trust store to verify those
# endpoints' TLS certificates, which distroless/static bundles
# (/etc/ssl/certs/ca-certificates.crt) and scratch does not. The :nonroot
# tag also ships a pre-created unprivileged user (uid/gid 65532), which
# satisfies the "run as non-root" requirement without a custom useradd step
# in a base image that has no shell or package manager to run one with.
#
# Build (from repo root):
#   docker build -f deploy/axon-relay/Dockerfile -t axon-relay .
#
# See deploy/axon-relay/README.md for running the resulting image.

FROM golang:1.27.3 AS builder

WORKDIR /src

# Cache module downloads separately from source changes.
COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ cmd/
COPY internal/ internal/
COPY pkg/ pkg/

# CGO_ENABLED=0 is belt-and-suspenders here (the module graph has no cgo
# dependency for this binary already) but makes the static-linking
# assumption explicit and keeps the build reproducible if that ever
# changes upstream.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/axon-relay ./cmd/axon-relay

FROM gcr.io/distroless/static:nonroot

# AXON_RELAY_DB_PATH defaults to axon-relay.db (relative to the working
# directory) in cmd/axon-relay/main.go. Pin a working directory here so
# that default resolves to a predictable absolute path regardless of how
# the container is invoked, and so it lines up with the volume mount
# documented in docker-compose.yml.
WORKDIR /var/lib/axon-relay

COPY --from=builder /out/axon-relay /usr/local/bin/axon-relay

# distroless/static:nonroot already runs as uid/gid 65532 ("nonroot"); this
# is explicit for clarity and so it survives if the base tag is ever
# swapped for a root-defaulting one.
USER 65532:65532

# AXON_RELAY_ADDR default (main.go) -- the WebSocket/HTTP connect endpoint.
EXPOSE 8080
# AXON_RELAY_METRICS_ADDR default (main.go) -- Prometheus /metrics and
# /healthz. Bound to 127.0.0.1 by default inside the container; see
# docker-compose.yml for how that interacts with host port publishing.
EXPOSE 9090

ENTRYPOINT ["/usr/local/bin/axon-relay"]
