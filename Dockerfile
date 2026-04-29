# syntax=docker/dockerfile:1.7
#
# Multi-stage build for the ZTP server, agent, and ctl. Uses BuildKit cache
# mounts so the Go module cache and build cache survive between rebuilds —
# typical incremental rebuilds finish in a couple of seconds.
#
# Build:    DOCKER_BUILDKIT=1 docker build --target server -t ztp-server .
# Cross:    docker build --build-arg TARGETARCH=arm64 --target agent -t ztp-agent .

ARG GO_VERSION=1.26

# ---------------------------------------------------------------------- deps -
# Layer that warms up the Go module cache. Re-runs only when go.{mod,sum}
# change.
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS deps
WORKDIR /src
ENV CGO_ENABLED=0 GOFLAGS=-trimpath
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

# --------------------------------------------------------------------- build -
# Builder with full source tree. Cache mounts mean only changed packages get
# recompiled.
FROM --platform=$BUILDPLATFORM deps AS build
ARG TARGETOS=linux
ARG TARGETARCH
ARG VERSION=docker
COPY . .

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -ldflags "-s -w -X main.Version=${VERSION}" -o /out/ztp-server ./cmd/ztp-server && \
    GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -ldflags "-s -w -X main.Version=${VERSION}" -o /out/ztp-agent  ./cmd/ztp-agent && \
    GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -ldflags "-s -w -X main.Version=${VERSION}" -o /out/ztpctl     ./cmd/ztpctl && \
    GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -ldflags "-s -w -X main.Version=${VERSION}" -o /out/ztp-mdns-publish ./cmd/ztp-mdns-publish

# -------------------------------------------------------------------- server -
FROM gcr.io/distroless/static-debian12:nonroot AS server
COPY --from=build /out/ztp-server /ztp-server
COPY --from=build /out/ztpctl     /ztpctl
# The shell agent script is hosted at GET /v1/agent.sh so devices can
# bootstrap with `curl -fsSL .../v1/agent.sh | sh`.
COPY scripts/agent/ztp-agent.sh /usr/local/share/ztp/ztp-agent.sh
EXPOSE 8080
USER nonroot
ENTRYPOINT ["/ztp-server"]
CMD ["-config", "/etc/ztp/ztp-server.yaml"]

# --------------------------------------------------------------------- agent -
# A "device" image: alpine so we have a real shell + curl + jq for drop-in
# POSIX appliers, plus the Go agent binary.
FROM alpine:3.20 AS agent
RUN apk add --no-cache jq curl openssl ca-certificates bash coreutils
COPY --from=build /out/ztp-agent /usr/local/bin/ztp-agent
COPY scripts/agent/ztp-agent.sh   /usr/local/bin/ztp-agent.sh
COPY scripts/appliers/            /etc/ztp/appliers.d/
RUN chmod +x /etc/ztp/appliers.d/*.sh /usr/local/bin/ztp-agent.sh
ENTRYPOINT ["/usr/local/bin/ztp-agent"]

# --------------------------------------------------------------- agent-shell -
# A "device" image that runs ONLY the POSIX shell agent — no Go binary, no
# jq required (the shell agent uses Accept: text/plain). Useful for
# demonstrating the small-footprint deployment path on minimal base images.
# We still install jq + bash here so operator-supplied appliers that prefer
# them work; remove from the apk add line to verify the no-jq path.
FROM alpine:3.20 AS agent-shell
# busybox already provides awk, sed, base64, head, tr, etc.
RUN apk add --no-cache curl openssl ca-certificates jq
COPY scripts/agent/ztp-agent.sh   /usr/local/bin/ztp-agent.sh
COPY scripts/appliers/            /etc/ztp/appliers.d/
RUN chmod +x /etc/ztp/appliers.d/*.sh /usr/local/bin/ztp-agent.sh
ENTRYPOINT ["/usr/local/bin/ztp-agent.sh"]

# --------------------------------------------------------------------- ctl ---
FROM gcr.io/distroless/static-debian12:nonroot AS ctl
COPY --from=build /out/ztpctl /ztpctl
ENTRYPOINT ["/ztpctl"]

# --------------------------------------------------------------------- mdns --
# Standalone DNS-SD advertiser. Runs in `network_mode: host` next to the
# server so multicast (UDP 5353) actually reaches the LAN — the in-server
# mDNS publisher can't escape Docker bridge networking.
FROM gcr.io/distroless/static-debian12:nonroot AS mdns
COPY --from=build /out/ztp-mdns-publish /ztp-mdns-publish
ENTRYPOINT ["/ztp-mdns-publish"]
