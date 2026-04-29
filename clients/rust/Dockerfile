# syntax=docker/dockerfile:1.7
#
# Multi-stage Rust builder for the ztp-agent.
#
# Uses cargo-chef so the dependency layer is cached separately from the
# application source — rebuilds after a code change only recompile the crate
# itself, not the full dependency tree.
#
# Build arguments
#   TARGET   Rust target triple (default: x86_64-unknown-linux-musl)
#   FEATURES Comma-separated Cargo feature list (default: mdns)
#   EXTRA_PKGS  Extra apt packages (e.g. for BLE cross targets)
#
# Two families of targets are supported:
#
#   musl  (*-unknown-linux-musl / *-unknown-linux-musleabihf)
#         Fully-static binaries; cannot link against glibc's libdbus.
#         Use for non-BLE deployments where a single static binary is ideal.
#
#   gnu   (*-unknown-linux-gnu / *-unknown-linux-gnueabihf)
#         Dynamically links against glibc; required when the `ble` feature is
#         enabled because libdbus-1 is a glibc library. Works on any standard
#         Linux distro (Debian, Ubuntu, Raspberry Pi OS, …).
#
# Examples
#   # amd64 musl, mdns only (default)
#   docker build -f clients/rust/Dockerfile --output type=local,dest=bin .
#
#   # arm64 gnu + mdns + BLE
#   docker build -f clients/rust/Dockerfile \
#     --build-arg TARGET=aarch64-unknown-linux-gnu \
#     --build-arg FEATURES=mdns,ble \
#     --build-arg EXTRA_PKGS="libdbus-1-dev:arm64" \
#     --output type=local,dest=bin .

ARG RUST_VERSION=1
ARG TARGET=x86_64-unknown-linux-musl
ARG FEATURES=mdns
# Extra apt packages needed for the target (e.g. "libdbus-1-dev:arm64" for BLE cross).
ARG EXTRA_PKGS=""

# ── chef planner ──────────────────────────────────────────────────────────────
# Computes the "recipe" (dependency manifest) from Cargo.toml / Cargo.lock.
# This layer only invalidates when those files change.
FROM rust:${RUST_VERSION} AS chef
RUN cargo install cargo-chef --locked
WORKDIR /src

FROM chef AS planner
COPY clients/rust/ .
RUN cargo chef prepare --recipe-path recipe.json

# ── builder ───────────────────────────────────────────────────────────────────
# Installs cross-compilation toolchains for both musl and gnu targets, then
# cooks (pre-builds) all dependencies.
# The cook layer is cached as long as recipe.json + TARGET + FEATURES are
# unchanged — only the final `cargo build` re-runs on source edits.
FROM chef AS builder
ARG TARGET
ARG FEATURES
ARG EXTRA_PKGS

# Enable multi-arch apt so we can install foreign-arch sysroot libs for BLE.
RUN dpkg --add-architecture arm64 2>/dev/null || true && \
    dpkg --add-architecture armhf 2>/dev/null || true && \
    apt-get update -qq && \
    apt-get install -y --no-install-recommends \
        musl-tools \
        gcc-aarch64-linux-gnu \
        gcc-arm-linux-gnueabihf \
        pkg-config \
        ${EXTRA_PKGS} && \
    rm -rf /var/lib/apt/lists/*

# Add all the Rust targets we might need.
RUN rustup target add \
        x86_64-unknown-linux-musl \
        aarch64-unknown-linux-musl \
        armv7-unknown-linux-musleabihf \
        aarch64-unknown-linux-gnu \
        armv7-unknown-linux-gnueabihf

# Linker overrides for every cross target (musl and gnu share the same
# gcc cross-compiler — the difference is only in the Rust std library used).
ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-linux-gnu-gcc \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
    CARGO_TARGET_ARMV7_UNKNOWN_LINUX_MUSLEABIHF_LINKER=arm-linux-gnueabihf-gcc \
    CARGO_TARGET_ARMV7_UNKNOWN_LINUX_GNUEABIHF_LINKER=arm-linux-gnueabihf-gcc \
    CC_aarch64_unknown_linux_musl=aarch64-linux-gnu-gcc \
    CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
    CC_armv7_unknown_linux_musleabihf=arm-linux-gnueabihf-gcc \
    CC_armv7_unknown_linux_gnueabihf=arm-linux-gnueabihf-gcc

WORKDIR /src

# Cook dependencies — the expensive / cached layer.
COPY --from=planner /src/recipe.json recipe.json
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo chef cook --release --target ${TARGET} \
        $(echo ${FEATURES} | sed 's/^/--features /') \
        --recipe-path recipe.json

# Build the actual binary.
COPY clients/rust/ .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --target ${TARGET} \
        $(echo ${FEATURES} | sed 's/^/--features /') && \
    # Copy the finished binary out of the (cached) target dir so the
    # output stage can always find it.
    cp target/${TARGET}/release/ztp-agent /ztp-agent

# ── output ────────────────────────────────────────────────────────────────────
# Scratch stage used with --output type=local,dest=<dir> to extract only the
# binary.
FROM scratch AS output
COPY --from=builder /ztp-agent /ztp-agent
