set dotenv-path := "deploy/.env"

# tedge-zerotouch-provisioning — task runner
#
# Install just: brew install just / cargo install just
#
# Use `just` to list tasks, `just <task>` to run one.

set shell := ["bash", "-cu"]
set positional-arguments

go        := env_var_or_default("GO", "go")
goflags   := "-trimpath"
ldflags   := "-s -w"
bin_dir   := "bin"

# default
default:
    @just --list

# ---- build ------------------------------------------------------------------

# Build all three binaries (server, agent, ctl)
build: server agent ctl

server:
    CGO_ENABLED=0 {{go}} build {{goflags}} -ldflags '{{ldflags}}' -o {{bin_dir}}/ztp-server ./cmd/ztp-server

agent:
    CGO_ENABLED=0 {{go}} build {{goflags}} -ldflags '{{ldflags}}' -o {{bin_dir}}/ztp-agent ./cmd/ztp-agent

# Build the agent with BLE transport compiled in (Linux/Windows GATT peripheral).
# The resulting binary supports -transport http|ble|auto (default: auto).
# NOTE: the GATT peripheral only works on Linux/Windows. To deploy to a Linux
# device from macOS, use `just cross-agent-ble` instead.
agent-ble:
    {{go}} build {{goflags}} -tags ble -ldflags '{{ldflags}}' -o {{bin_dir}}/ztp-agent-ble ./cmd/ztp-agent

# Cross-compile the BLE agent for a Linux device (e.g. Raspberry Pi).
# BLE peripheral mode requires Linux (BlueZ); this is the typical deployment target.
#   just cross-agent-ble        # linux/amd64 (default)
#   just cross-agent-ble arm64  # Raspberry Pi 4 / arm64
cross-agent-ble arch="amd64":
    GOOS=linux GOARCH={{arch}} {{go}} build {{goflags}} -tags ble -ldflags '{{ldflags}}' -o {{bin_dir}}/ztp-agent-ble-linux-{{arch}} ./cmd/ztp-agent

ctl:
    CGO_ENABLED=0 {{go}} build {{goflags}} -ldflags '{{ldflags}}' -o {{bin_dir}}/ztpctl ./cmd/ztpctl

# Cross-compile a static linux/$arch agent
cross-agent arch="amd64":
    GOOS=linux GOARCH={{arch}} CGO_ENABLED=0 {{go}} build {{goflags}} -ldflags '{{ldflags}}' -o {{bin_dir}}/ztp-agent-linux-{{arch}} ./cmd/ztp-agent

# ---- quality ----------------------------------------------------------------

test *args:
    {{go}} test ./... {{args}}

vet:
    {{go}} vet ./...

tidy:
    {{go}} mod tidy

clean:
    rm -rf {{bin_dir}} {{pkg_dir}} data

clean-dist:
    rm -rf {{pkg_dir}}

# ---- rust client ------------------------------------------------------------

rust_dir   := "clients/rust"
rust_bin   := "ztp-agent"

# Build the Rust agent for the host platform (debug by default; pass `profile=release` to optimise).
# Note: `--features ble` is intentionally excluded here because it requires Linux/BlueZ.
#       Use `rust-agent-linux-*` targets to produce BLE-capable binaries.
rust-agent profile="debug":
    #!/usr/bin/env bash
    set -eu
    cd {{rust_dir}}
    if [ "{{profile}}" = "release" ]; then
        cargo build --release --features mdns
        cp target/release/{{rust_bin}} ../../{{bin_dir}}/{{rust_bin}}-rust
    else
        cargo build --features mdns
        cp target/debug/{{rust_bin}} ../../{{bin_dir}}/{{rust_bin}}-rust-debug
    fi

# Build the Rust agent for Linux amd64 (static musl).
# Requires: rustup target add x86_64-unknown-linux-musl
#           cargo install cargo-zigbuild
# Note: --features ble is excluded; bluer/libdbus-sys cannot cross-compile from macOS.
#       Use just rust-agent-linux-ble on a Linux host for a BLE-capable binary.
rust-agent-linux-amd64:
    cd {{rust_dir}} && cargo zigbuild --release --features mdns --target x86_64-unknown-linux-musl
    cp {{rust_dir}}/target/x86_64-unknown-linux-musl/release/{{rust_bin}} \
        {{bin_dir}}/{{rust_bin}}-rust-linux-amd64

# Build the Rust agent for Linux arm64 (static musl).
# Requires: rustup target add aarch64-unknown-linux-musl
#           cargo install cargo-zigbuild
# Note: --features ble is excluded; bluer/libdbus-sys cannot cross-compile from macOS.
#       Use just rust-agent-linux-ble on a Linux host for a BLE-capable binary.
rust-agent-linux-arm64:
    cd {{rust_dir}} && cargo zigbuild --release --features mdns --target aarch64-unknown-linux-musl
    cp {{rust_dir}}/target/aarch64-unknown-linux-musl/release/{{rust_bin}} \
        {{bin_dir}}/{{rust_bin}}-rust-linux-arm64

# Build the Rust agent for Linux armv7 / armhf (Raspberry Pi 2/3 32-bit).
# Requires: rustup target add armv7-unknown-linux-musleabihf
#           cargo install cargo-zigbuild
# Note: --features ble is excluded; bluer/libdbus-sys cannot cross-compile from macOS.
#       Use just rust-agent-linux-ble on a Linux host for a BLE-capable binary.
rust-agent-linux-armv7:
    cd {{rust_dir}} && cargo zigbuild --release --features mdns --target armv7-unknown-linux-musleabihf
    cp {{rust_dir}}/target/armv7-unknown-linux-musleabihf/release/{{rust_bin}} \
        {{bin_dir}}/{{rust_bin}}-rust-linux-armv7

# Build a BLE-capable Rust agent on a Linux host (requires BlueZ + libdbus-1-dev).
# Run this recipe directly on the target Linux machine or inside a Linux container:
#   docker run --rm -v $PWD:/src -w /src/clients/rust rust:slim \
#     bash -c "apt-get update && apt-get install -y libdbus-1-dev pkg-config && \
#              cargo build --release --features 'mdns,ble'"
rust-agent-linux-ble:
    cd {{rust_dir}} && cargo build --release --features "mdns,ble"
    cp {{rust_dir}}/target/release/{{rust_bin}} {{bin_dir}}/{{rust_bin}}-rust-linux-ble

# Build all Rust targets (host + linux/amd64 + linux/arm64 + linux/armv7)
rust-agent-all: rust-agent rust-agent-linux-amd64 rust-agent-linux-arm64 rust-agent-linux-armv7

# ---- Docker-based Rust cross-compilation ------------------------------------
# Use these when you don't have cargo-zigbuild / Zig installed locally, or
# when you want a self-contained, reproducible build environment on macOS.
#
# The builder image is cached in Docker (layer cache + BuildKit cache mounts)
# so subsequent builds only recompile changed source, not the full dep tree.
#
# Two target families:
#
#   musl  (*-unknown-linux-musl)  — fully-static binaries, mdns only.
#         libdbus-1 is a glibc library; it cannot be linked into a musl binary.
#         Good for minimal/embedded deployments that don't need BLE.
#
#   gnu   (*-unknown-linux-gnu)   — glibc dynamic binaries, mdns + BLE.
#         Required for BLE because bluer depends on D-Bus (libdbus-1).
#         Runs on any standard Linux distro (Debian, Ubuntu, Raspberry Pi OS).
#
# Usage:
#   just rust-docker-amd64        # linux/amd64 musl, mdns
#   just rust-docker-arm64        # linux/arm64 musl, mdns
#   just rust-docker-armv7        # linux/armv7 musl, mdns
#   just rust-docker-amd64-ble    # linux/amd64 gnu, mdns + BLE
#   just rust-docker-arm64-ble    # linux/arm64 gnu, mdns + BLE
#   just rust-docker-armv7-ble    # linux/armv7 gnu, mdns + BLE
#   just rust-docker-all          # all six targets

# Internal helper — build via clients/rust/Dockerfile and copy output to bin/.
# Args: target (Rust triple), features (comma list), suffix (binary name suffix), extra_pkgs (apt)
_rust-docker target features suffix extra_pkgs="":
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p {{bin_dir}}
    DOCKER_BUILDKIT=1 docker build \
        --file clients/rust/Dockerfile \
        --target output \
        --build-arg TARGET={{target}} \
        --build-arg FEATURES={{features}} \
        --build-arg "EXTRA_PKGS={{extra_pkgs}}" \
        --output "type=local,dest=/tmp/ztp-rust-out-{{suffix}}" \
        .
    cp /tmp/ztp-rust-out-{{suffix}}/ztp-agent {{bin_dir}}/{{rust_bin}}-rust-{{suffix}}
    echo "→ {{bin_dir}}/{{rust_bin}}-rust-{{suffix}}"

# ── musl (static, no BLE) ────────────────────────────────────────────────────

# Cross-compile the Rust agent for Linux amd64 — static musl binary, mdns only.
rust-docker-amd64:
    just _rust-docker x86_64-unknown-linux-musl mdns linux-amd64

# Cross-compile the Rust agent for Linux arm64 — static musl binary, mdns only.
rust-docker-arm64:
    just _rust-docker aarch64-unknown-linux-musl mdns linux-arm64

# Cross-compile the Rust agent for Linux armv7/armhf — static musl binary, mdns only.
rust-docker-armv7:
    just _rust-docker armv7-unknown-linux-musleabihf mdns linux-armv7

# ── gnu (glibc, mdns + BLE) ──────────────────────────────────────────────────
# BLE requires libdbus-1 which is a glibc library; use *-unknown-linux-gnu
# targets so the linker can find it. libdbus-1-dev:<arch> is installed inside
# the builder image via EXTRA_PKGS.

# Cross-compile the Rust agent for Linux amd64 with BLE+mDNS — glibc binary.
rust-docker-amd64-ble:
    just _rust-docker x86_64-unknown-linux-gnu "mdns,ble" linux-amd64-ble \
        "libdbus-1-dev"

# Cross-compile the Rust agent for Linux arm64 with BLE+mDNS — glibc binary.
rust-docker-arm64-ble:
    just _rust-docker aarch64-unknown-linux-gnu "mdns,ble" linux-arm64-ble \
        "libdbus-1-dev:arm64"

# Cross-compile the Rust agent for Linux armv7/armhf with BLE+mDNS — glibc binary.
rust-docker-armv7-ble:
    just _rust-docker armv7-unknown-linux-gnueabihf "mdns,ble" linux-armv7-ble \
        "libdbus-1-dev:armhf"

# Build all Docker-based Rust cross targets (musl + BLE gnu for amd64/arm64/armv7).
rust-docker-all: rust-docker-amd64 rust-docker-arm64 rust-docker-armv7 rust-docker-amd64-ble rust-docker-arm64-ble rust-docker-armv7-ble

# Run the Rust agent unit + integration tests
rust-test *args:
    cd {{rust_dir}} && cargo test {{args}}

# ---- packaging (nfpm) -------------------------------------------------------
#
# Build .deb / .rpm packages using nfpm (https://github.com/goreleaser/nfpm).
#
# Install nfpm:
#   brew install goreleaser/tap/nfpm
#   # or:  go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest
#
# Two package configs are provided:
#   packaging/nfpm-go.yaml   — bundles the Go-compiled binary
#   packaging/nfpm-rust.yaml — bundles the Rust-compiled binary (static musl)
#
# Both packages install:
#   /usr/bin/ztp-agent                         — the agent binary
#   /usr/lib/ztp/ztp-agent-run                 — single-run launcher wrapper
#   /lib/systemd/system/ztp-agent.service      — oneshot systemd unit
#   /etc/default/ztp-agent                     — operator config (config|noreplace)
#   /etc/ztp/appliers.d/*.v2.sh                — v2 applier scripts (config|noreplace)
#   /etc/ztp/appliers.d/lib/ini.sh             — shared INI parser library
#   /etc/ztp/                                  — drop /etc/ztp/server.pub here for strict trust
#   /var/lib/ztp/                              — runtime state (identity key, provisioned flag)
#
# Arch mapping:
#   just-recipe-arch   NFPM_ARCH   Go BIN_ARCH   Rust BIN_ARCH
#   amd64              amd64       amd64         amd64
#   arm64              arm64       arm64         arm64
#   armhf              armhf       arm           armv7

pkg_dir := "dist"
nfpm    := "nfpm"

# Internal helper — package one variant.
# Args: nfpm_config, nfpm_arch, bin_arch, pkg_format, version
#
# nfpm does not expand env vars inside contents[].src glob paths, so we
# pre-process the config with envsubst into a temp file before invoking nfpm.
_pkg nfpm_config nfpm_arch bin_arch pkg_format version:
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p {{pkg_dir}}
    tmpconfig=$(mktemp /tmp/nfpm-XXXXXX.yaml)
    trap 'rm -f "$tmpconfig"' EXIT
    export VERSION="{{version}}" NFPM_ARCH="{{nfpm_arch}}" BIN_ARCH="{{bin_arch}}"
    envsubst < "{{nfpm_config}}" > "$tmpconfig"
    {{nfpm}} package \
        --config "$tmpconfig" \
        --packager {{pkg_format}} \
        --target {{pkg_dir}}
    echo "→ $(ls -1t {{pkg_dir}}/*.{{pkg_format}} 2>/dev/null | head -1)"

# Derive a version string from git tags (e.g. 1.2.3 or 1.2.3~git.abc1234).
_pkg-version:
    #!/usr/bin/env bash
    set -euo pipefail
    if git describe --tags --exact-match HEAD 2>/dev/null | grep -qE '^v?[0-9]+\.[0-9]+'; then
        git describe --tags --exact-match HEAD | sed 's/^v//'
    else
        BASE=$(git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//' || echo "0.0.0")
        SHA=$(git rev-parse --short HEAD)
        echo "${BASE}~git.${SHA}"
    fi

# ── Go agent packages ─────────────────────────────────────────────────────────

# Build a .deb for the Go agent (linux/amd64).
pkg-go-amd64 fmt="deb" ver="": cross-agent-ble
    #!/usr/bin/env bash
    set -euo pipefail
    VER="{{ver}}"; [ -z "$VER" ] && VER=$(just _pkg-version)
    just _pkg packaging/nfpm-go.yaml amd64 amd64 {{fmt}} "$VER"

# Build a .deb for the Go agent (linux/arm64).
pkg-go-arm64 fmt="deb" ver="":
    #!/usr/bin/env bash
    set -euo pipefail
    just cross-agent-ble arm64
    VER="{{ver}}"; [ -z "$VER" ] && VER=$(just _pkg-version)
    just _pkg packaging/nfpm-go.yaml arm64 arm64 {{fmt}} "$VER"

# Build a .deb for the Go agent (linux/armhf — Raspberry Pi 2/3 32-bit).
pkg-go-armhf fmt="deb" ver="":
    #!/usr/bin/env bash
    set -euo pipefail
    just cross-agent-ble arm
    VER="{{ver}}"; [ -z "$VER" ] && VER=$(just _pkg-version)
    just _pkg packaging/nfpm-go.yaml armhf arm {{fmt}} "$VER"

# Build .deb packages for the Go agent across all three architectures.
pkg-go-all fmt="deb" ver="": clean-dist (pkg-go-amd64 fmt ver) (pkg-go-arm64 fmt ver) (pkg-go-armhf fmt ver)

# ── Rust agent packages ───────────────────────────────────────────────────────

# Build a .deb for the Rust agent (linux/amd64, static musl).
# Requires the binary — run `just rust-docker-amd64` first if missing.
pkg-rust-amd64 fmt="deb" ver="": rust-docker-amd64
    #!/usr/bin/env bash
    set -euo pipefail
    VER="{{ver}}"; [ -z "$VER" ] && VER=$(just _pkg-version)
    just _pkg packaging/nfpm-rust.yaml amd64 amd64 {{fmt}} "$VER"

# Build a .deb for the Rust agent (linux/arm64, static musl).
# Requires the binary — run `just rust-docker-arm64` first if missing.
pkg-rust-arm64 fmt="deb" ver="": rust-docker-arm64
    #!/usr/bin/env bash
    set -euo pipefail
    VER="{{ver}}"; [ -z "$VER" ] && VER=$(just _pkg-version)
    just _pkg packaging/nfpm-rust.yaml arm64 arm64 {{fmt}} "$VER"

# Build a .deb for the Rust agent (linux/armhf — Raspberry Pi 2/3 32-bit, static musl).
# Requires the binary — run `just rust-docker-armv7` first if missing.
pkg-rust-armhf fmt="deb" ver="": rust-docker-armv7
    #!/usr/bin/env bash
    set -euo pipefail
    VER="{{ver}}"; [ -z "$VER" ] && VER=$(just _pkg-version)
    just _pkg packaging/nfpm-rust.yaml armhf armv7 {{fmt}} "$VER"

# Build .deb packages for the Rust agent across all three architectures.
pkg-rust-all fmt="deb" ver="": (pkg-rust-amd64 fmt ver) (pkg-rust-arm64 fmt ver) (pkg-rust-armhf fmt ver)

# ── Alpine (apk) packages ─────────────────────────────────────────────────────
#
# Alpine uses OpenRC, not systemd, so a separate set of recipes + nfpm configs
# (packaging/nfpm-alpine-{go,rust}.yaml) is needed. Same binary inputs as the
# .deb/.rpm recipes; the format differs only in the init system + arch naming
# (apk uses x86_64 / aarch64 / armv7 instead of amd64 / arm64 / armhf).

# Build a .apk for the Go agent (linux/amd64).
pkg-alpine-go-amd64 ver="": cross-agent-ble
    #!/usr/bin/env bash
    set -euo pipefail
    VER="{{ver}}"; [ -z "$VER" ] && VER=$(just _pkg-version)
    just _pkg packaging/nfpm-alpine-go.yaml x86_64 amd64 apk "$VER"

# Build a .apk for the Go agent (linux/arm64).
pkg-alpine-go-arm64 ver="":
    #!/usr/bin/env bash
    set -euo pipefail
    just cross-agent-ble arm64
    VER="{{ver}}"; [ -z "$VER" ] && VER=$(just _pkg-version)
    just _pkg packaging/nfpm-alpine-go.yaml aarch64 arm64 apk "$VER"

# Build a .apk for the Go agent (linux/armhf — Raspberry Pi 2/3 32-bit).
pkg-alpine-go-armhf ver="":
    #!/usr/bin/env bash
    set -euo pipefail
    just cross-agent-ble arm
    VER="{{ver}}"; [ -z "$VER" ] && VER=$(just _pkg-version)
    just _pkg packaging/nfpm-alpine-go.yaml armv7 arm apk "$VER"

# Build .apk packages for the Go agent across all three architectures.
pkg-alpine-go-all ver="": (pkg-alpine-go-amd64 ver) (pkg-alpine-go-arm64 ver) (pkg-alpine-go-armhf ver)

# Build a .apk for the Rust agent (linux/amd64, static musl).
pkg-alpine-rust-amd64 ver="": rust-docker-amd64
    #!/usr/bin/env bash
    set -euo pipefail
    VER="{{ver}}"; [ -z "$VER" ] && VER=$(just _pkg-version)
    just _pkg packaging/nfpm-alpine-rust.yaml x86_64 amd64 apk "$VER"

# Build a .apk for the Rust agent (linux/arm64, static musl).
pkg-alpine-rust-arm64 ver="": rust-docker-arm64
    #!/usr/bin/env bash
    set -euo pipefail
    VER="{{ver}}"; [ -z "$VER" ] && VER=$(just _pkg-version)
    just _pkg packaging/nfpm-alpine-rust.yaml aarch64 arm64 apk "$VER"

# Build a .apk for the Rust agent (linux/armhf — Raspberry Pi 2/3 32-bit).
pkg-alpine-rust-armhf ver="": rust-docker-armv7
    #!/usr/bin/env bash
    set -euo pipefail
    VER="{{ver}}"; [ -z "$VER" ] && VER=$(just _pkg-version)
    just _pkg packaging/nfpm-alpine-rust.yaml armv7 armv7 apk "$VER"

# Build .apk packages for the Rust agent across all three architectures.
pkg-alpine-rust-all ver="": (pkg-alpine-rust-amd64 ver) (pkg-alpine-rust-arm64 ver) (pkg-alpine-rust-armhf ver)

# ---- web --------------------------------------------------------------------

web-install:
    cd web && pnpm install

web-dev:
    cd web && pnpm dev

web-build:
    cd web && pnpm build
    just web-embed-sync

# ---- desktop app (Wails) ----------------------------------------------------

# Build a fully-packaged app using the wails CLI. Handles icon conversion,
# platform bundle structure, and resource embedding automatically.
#
# Output (relative to project root):
#   macOS   → build/bin/ztp-app.app  — proper .app bundle; icon appears in
#             Dock and Cmd+Tab task-switcher (read from iconfile.icns inside
#             the bundle, generated from build/appicon.png).
#   Windows → build/bin/ztp-app.exe  — icon embedded in PE resource section.
#   Linux   → build/bin/ztp-app      — GTK window icon set at runtime from
#             the embedded PNG; add a .desktop file for launcher icon.
#
# Prerequisites:
#   wails CLI  — go install github.com/wailsapp/wails/v2/cmd/wails@latest
#   macOS      — Xcode CLT (xcode-select --install)
#   Linux      — libgtk-3-dev libwebkit2gtk-4.0-dev (apt) or equivalent
#   Windows    — MSVC or MinGW-w64 (CGO required); build natively or in CI
#
# CGO_LDFLAGS: macOS 14+ requires UniformTypeIdentifiers linked explicitly.
app-bundle:
    cd cmd/ztp-app && CGO_LDFLAGS="-framework UniformTypeIdentifiers" wails build -tags ble -clean

# Smart rebuild for the dev loop: the first call runs app-bundle to create the
# platform bundle (slow, happens once). Subsequent calls replace only the Go
# binary inside the existing bundle (fast — skips the frontend pipeline and
# wails scaffolding). The bundle icon, plist, and resources stay intact.
#
# On macOS the bundle lives at cmd/ztp-app/build/bin/ztp-app.app.
# On Linux/Windows app-bundle is always re-run (no partial-update shortcut).
app-build:
    #!/usr/bin/env bash
    set -euo pipefail
    case "$(uname -s)" in
    Darwin)
        bundle=cmd/ztp-app/build/bin/ztp-app.app
        if [[ ! -d "$bundle" ]]; then
            just app-bundle
        else
            CGO_ENABLED=1 CGO_LDFLAGS="-framework UniformTypeIdentifiers" \
                {{go}} build {{goflags}} -tags 'production ble' \
                -o "$bundle/Contents/MacOS/ztp-app" ./cmd/ztp-app
        fi
        ;;
    *)
        just app-bundle
        ;;
    esac

# Run the desktop app with a fresh in-memory session.
#
# macOS: opens the .app bundle — icon shows correctly in the Dock and Cmd+Tab
# switcher. `open` returns immediately; close the previous window before
# re-running to avoid duplicate instances.
# Linux/Windows: run cmd/ztp-app/build/bin/ztp-app directly after `just app-bundle`.
app-dev: app-build
    open cmd/ztp-app/build/bin/ztp-app.app

# Run the desktop app against the docker stack's persistent state
# (deploy/data/ + deploy/profiles.d/). Stop `just up` first — SQLite
# cannot be safely opened by two writers.
app-dev-deploy: app-build
    open cmd/ztp-app/build/bin/ztp-app.app --args -config deploy/config/ztp-app.yaml

# Run the desktop app with LAN listener + mDNS-SD advertisement so
# devices running ztp-agent (no -server flag) discover it automatically.
# Defaults to :8080; pass -listen <addr> to override.
# Verify the announce on macOS with `dns-sd -B _ztp._tcp` or on
# Linux with `avahi-browse -r _ztp._tcp`.
app-dev-mdns: app-build
    open cmd/ztp-app/build/bin/ztp-app.app --args -mdns

# Mirror web/build/ into internal/server/web/dist/ so `go build` can
# embed the freshly-built SPA. Kept as its own recipe so callers who
# already produced web/build/ via a different toolchain (e.g. CI
# artefact download) can stamp the embed without re-running pnpm.
web-embed-sync:
    rm -rf internal/server/web/dist
    mkdir -p internal/server/web/dist
    cp -R web/build/. internal/server/web/dist/
    # Restore the .gitkeep + .gitignore scaffold so the dir keeps
    # behaving the same on a fresh clone.
    : > internal/server/web/dist/.gitkeep
    printf '# Built SPA artefacts populated by `just web-build` (which copies\n# web/build/ here). Keep the directory committed via .gitkeep so\n# go:embed succeeds even on a fresh clone, but never commit the\n# generated files.\n*\n!.gitkeep\n!.gitignore\n' > internal/server/web/dist/.gitignore

# ---- docker / compose -------------------------------------------------------

# Build docker images (server + agent + web). Uses BuildKit cache mounts so
# rebuilds reuse the Go module / build cache.
docker-build:
    DOCKER_BUILDKIT=1 docker compose -f deploy/docker-compose.yaml --env-file deploy/.env build

# Bootstrap deploy/.env on first run with a strong random admin token.
# Idempotent: re-running leaves an existing .env untouched.
init:
    #!/usr/bin/env bash
    set -eu
    env_file="deploy/.env"
    if [ -f "$env_file" ]; then
        echo "deploy/.env already exists — leaving it alone."
        exit 0
    fi
    token="$(openssl rand -hex 32)"
    cat > "$env_file" <<EOF
    # Auto-generated by \`just init\` on $(date -u +%FT%TZ).
    # Edit ZTP_SITE_ADDRESS / ZTP_TLS_EMAIL to deploy publicly. See .env.example.
    ZTP_ADMIN_TOKEN=$token
    ZTP_SITE_ADDRESS=localhost
    ZTP_TLS_EMAIL=internal
    ZTP_HTTPS_PORT=8443
    EOF
    chmod 600 "$env_file"
    echo "Wrote $env_file with a fresh ZTP_ADMIN_TOKEN."

# Bring up the full local stack: Caddy (TLS) + server + web SPA + demo devices.
# Auto-creates deploy/.env on first run with a random admin token.
#
# Open https://localhost:8443/   (browser will warn — accept the local CA, or
#                                 import deploy/data-volume CA for clean trust)
# SPA:  http://localhost:5175/
#
# C8Y env vars (C8Y_BASEURL/C8Y_HOST/C8Y_URL, C8Y_TENANT, C8Y_USER/C8Y_USERNAME,
# C8Y_PASSWORD) are forwarded into the server container so the Cumulocity
# issuer can mint enrollment tokens.
up *args="": init
    docker compose -f deploy/docker-compose.yaml --env-file deploy/.env up --build {{args}}
    @echo
    @echo "── ZTP stack up ──"
    @echo "  UI + API:     https://localhost:8443/        (TLS, canonical)"
    @[ -n "${ZTP_HOST_IP:-}" ] && echo "  LAN (by IP):  https://${ZTP_HOST_IP}:8443/  (run 'just mkcert-setup' first)" || true
    @echo "  admin token:  see deploy/.env (ZTP_ADMIN_TOKEN)"

down:
    docker compose -f deploy/docker-compose.yaml --env-file deploy/.env down -v

logs *args:
    docker compose -f deploy/docker-compose.yaml --env-file deploy/.env logs -f {{args}}

# Run a single fresh device container against the running stack so you can
# watch enrollment + manual approval cycle.
device id="dev-$(uuidgen | head -c 8)":
    docker compose -f deploy/docker-compose.yaml --env-file deploy/.env run --rm -v /var/lib/ztp -e ZTP_DEVICE_ID={{id}} device

# Same as `device`, but uses the POSIX shell agent (no Go binary, no jq).
# `-v /var/lib/ztp` overlays an anonymous volume so this ad-hoc run gets a
# fresh Ed25519 identity instead of reusing the persistent shell-device-1
# keypair (which would cause the server to dedupe the pending entry by pubkey
# and silently keep the original device_id).
device-shell id="shell-$(uuidgen | head -c 8)":
    docker compose -f deploy/docker-compose.yaml --env-file deploy/.env run --rm -v /var/lib/ztp -e ZTP_DEVICE_ID={{id}} device-shell

# ---- minimal stack ----------------------------------------------------------
#
# Single-container deployment: just ztp-server, exposed directly on the host
# as plain HTTP (no Caddy, no SPA dev container, no demo devices). Reuses
# deploy/config/ztp-server.yaml + deploy/data/ + deploy/profiles.d/, so you
# can switch between the full stack and this one without losing the server's
# identity. Mutually exclusive with `just up` — both bind container_name
# `ztp-server`. Run `just web-build` before `up-minimal` if you want the
# embedded SPA at /, otherwise / serves the placeholder.

up-minimal *args="": init
    docker compose -f deploy/docker-compose.minimal.yaml --env-file deploy/.env up --build {{args}}
    @echo
    @echo "── ZTP minimal stack up ──"
    @echo "  UI + API:     http://localhost:${ZTP_HTTP_PORT:-8080}/   (plain HTTP)"
    @echo "  admin token:  see deploy/.env (ZTP_ADMIN_TOKEN)"

down-minimal:
    docker compose -f deploy/docker-compose.minimal.yaml --env-file deploy/.env down -v

logs-minimal *args:
    docker compose -f deploy/docker-compose.minimal.yaml --env-file deploy/.env logs -f {{args}}

# ---- mDNS / LAN discovery ---------------------------------------------------

# Linux / AWS: start the host-networked mDNS sidecar that advertises
# _ztp._tcp on the host's LAN. The sidecar lives in the `mdns` compose
# profile so `just up` doesn't pull it in by default.
mdns-publish:
    docker compose -f deploy/docker-compose.yaml --env-file deploy/.env --profile mdns up -d --build mdns
    @echo "advertising _ztp._tcp on the host LAN — `docker logs -f ztp-mdns` to watch"

mdns-stop:
    docker compose -f deploy/docker-compose.yaml --env-file deploy/.env --profile mdns rm -sf mdns

# ---- secrets ---------------------------------------------------------------

# Local-stack convenience wrappers around `ztpctl secrets …`. They use the
# server-managed age key under deploy/data/ that `just up` auto-generates,
# so neither the operator nor the server needs any extra setup.
#
# For multi-operator deployments use `ztpctl secrets …` directly with
# --recipient flags pointing at every operator's pubkey, or list those
# pubkeys under `age_recipients:` in deploy/config/ztp-server.yaml.

# Seal a profile in place. Defaults to encrypting common secret-shaped keys;
# pass a different regex with `just secrets-seal <file> '<regex>'`.
secrets-seal file="deploy/profiles.d/default.yaml" regex='^(password|bootstrap_token|.*token.*|.*secret.*)$':
    @test -f deploy/data/age.key.pub || { echo "deploy/data/age.key.pub missing — run 'just up' first" >&2; exit 1; }
    ./bin/ztpctl secrets seal {{file}} \
        --regex '{{regex}}' \
        --recipient "$(cat deploy/data/age.key.pub)"

# Open a sealed profile in $EDITOR; saves are re-encrypted automatically.
secrets-edit file="deploy/profiles.d/default.yaml":
    @test -f deploy/data/age.key || { echo "deploy/data/age.key missing — run 'just up' first" >&2; exit 1; }
    ./bin/ztpctl secrets edit {{file}} \
        --age-key-file deploy/data/age.key \
        --recipient "$(cat deploy/data/age.key.pub)"

# Print the decrypted plaintext to stdout (gated by --yes-show-secrets).
secrets-reveal file="deploy/profiles.d/default.yaml":
    @test -f deploy/data/age.key || { echo "deploy/data/age.key missing — run 'just up' first" >&2; exit 1; }
    ./bin/ztpctl secrets reveal {{file}} \
        --age-key-file deploy/data/age.key \
        --yes-show-secrets

# ---- mDNS / LAN discovery ---------------------------------------------------

# macOS / colima: host networking only reaches the colima VM, so we register
# directly with the Mac's mDNSResponder via dns-sd. Runs in the foreground;
# Ctrl-C unregisters.
mdns-publish-macos:
    ./scripts/mdns-publish-macos.sh

# ---- TLS certificates -------------------------------------------------------

# Generate a locally-trusted TLS certificate for ztp.local (and localhost)
# using mkcert. On first run mkcert installs its CA into the macOS/Firefox
# trust stores so browsers accept the cert without a warning.
#
# After running, activate the mkcert Caddyfile in deploy/.env:
#   ZTP_CADDYFILE=./Caddyfile.mkcert
#   ZTP_SITE_ADDRESS=ztp.local
# Then restart: just down && just up -d
mkcert-setup:
    #!/usr/bin/env bash
    set -eu
    if ! command -v mkcert >/dev/null 2>&1; then
        echo "mkcert not found. Install it first:" >&2
        echo "  brew install mkcert" >&2
        exit 1
    fi
    mkcert -install
    mkdir -p deploy/certs

    # Collect LAN IPv4 addresses (non-loopback) and the short hostname so
    # devices on the same subnet can connect via IP without needing mDNS.
    if [[ "$(uname)" == "Darwin" ]]; then
        lan_ips=$(ifconfig | awk '/inet / && !/127\.0\.0\.1/ {print $2}' | tr '\n' ' ')
    else
        lan_ips=$(hostname -I 2>/dev/null \
            | tr ' ' '\n' \
            | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' \
            | grep -v '^127\.' \
            | tr '\n' ' ' || true)
    fi
    host_name=$(hostname -s 2>/dev/null || hostname)
    primary_ip=$(echo "$lan_ips" | awk '{print $1}')

    echo "Detected LAN IPs: ${lan_ips:-<none>}"
    echo "Detected hostname: ${host_name}"

    # shellcheck disable=SC2086
    mkcert -cert-file deploy/certs/cert.pem -key-file deploy/certs/key.pem \
        ztp.local localhost 127.0.0.1 ::1 ${host_name} ${lan_ips}
    chmod 600 deploy/certs/key.pem

    # Persist settings in deploy/.env (idempotent sed-based upsert)
    env_file="deploy/.env"
    pairs=("ZTP_CADDYFILE=./Caddyfile.mkcert" "ZTP_SITE_ADDRESS=ztp.local")
    [[ -n "$primary_ip" ]] && pairs+=("ZTP_HOST_IP=${primary_ip}")
    for pair in "${pairs[@]}"; do
        key="${pair%%=*}"
        if grep -q "^${key}=" "$env_file" 2>/dev/null; then
            sed -i.bak "s|^${key}=.*|${pair}|" "$env_file" && rm -f "${env_file}.bak"
        else
            echo "${pair}" >> "$env_file"
        fi
    done
    echo ""
    echo "Done. Restart the stack to use the mkcert certificate:"
    echo "  just down && just up -d"
    echo ""
    echo "The stack will then be reachable at:"
    echo "  https://ztp.local:8443/      (mDNS-capable clients)"
    echo "  https://localhost:8443/      (clients without mDNS, same cert)"
    [[ -n "$primary_ip" ]] && echo "  https://${primary_ip}:8443/  (LAN devices connecting by IP)"
    true

# Sanity-check: who's announcing _ztp._tcp on this LAN right now?
mdns-discover:
    @if command -v dns-sd >/dev/null 2>&1; then \
        echo "dns-sd -B _ztp._tcp (Ctrl-C to stop)"; dns-sd -B _ztp._tcp; \
    elif command -v avahi-browse >/dev/null 2>&1; then \
        avahi-browse -rt _ztp._tcp; \
    else \
        echo "neither dns-sd nor avahi-browse found"; exit 1; \
    fi

# ---- developer convenience --------------------------------------------------

# Run the server locally with the example config (in-memory store).
run-server:
    {{bin_dir}}/ztp-server -config examples/ztp-server.yaml -v

# Print the server's public key (so devices can trust it).
server-pubkey config="examples/ztp-server.yaml":
    @{{bin_dir}}/ztp-server -config {{config}} -print-pubkey
