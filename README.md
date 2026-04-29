# tedge-zerotouch-provisioning

A composable Zero-Touch Provisioning (ZTP) system for thin-edge.io devices.

The same single binary runs **on a laptop on the local LAN**, **in the cloud
(AWS/Azure/GCP)**, or **as a relay between BLE devices and a remote server**.
Operators pick which trust mechanisms (allowlist, bootstrap token, manual
approval, TPM attestation, mTLS) and which payload modules (WiFi credentials,
SSH authorized_keys, Cumulocity config, file drops, post-hook) they want.

Devices run either a small static Go binary or a pure POSIX shell script.
Both delegate every payload type to **drop-in shell appliers** under
`/etc/ztp/appliers.d/<type>.sh` so device images can override behaviour
without recompiling anything.

## Status

- [x] Wire protocol (`pkg/protocol`) — Ed25519 signed envelopes, JCS canonical JSON
- [x] X25519 + ChaCha20-Poly1305 end-to-end bundle encryption (untrusted-relay safe)
- [x] Server engine + verifier chain (allowlist, bootstrap-token, known-keypair, TPM stub)
- [x] Payload providers (wifi, ssh, cumulocity, files, hook)
- [x] Per-module sealing for sensitive payloads (X25519+ChaCha20-Poly1305) so
      the ZTP server never persists Cumulocity enrollment tokens in plaintext
- [x] Pluggable Cumulocity enrollment-token issuer (`local`, `remote` mTLS
      sidecar, `static` for tests) — see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- [x] HTTPS transport + admin REST API + SSE pending-stream
- [x] Device agent (Go) with drop-in POSIX applier dispatch
- [x] POSIX shell agent fallback (`scripts/agent/ztp-agent.sh`)
- [x] `ztpctl` admin CLI
- [x] mDNS LAN discovery (server advertises, agent uses `-mdns`)
- [x] Persistent SQLite store (`store.driver: sqlite`)
- [x] Svelte 5 SPA (`web/`) — pending / devices / allowlist / tokens / audit
- [x] BLE GATT transport (build-tagged: `-tags ble`; device peripheral + central relay)

## Quick start (Docker Compose)

The fastest way to see the whole stack working:

```sh
just up
```

On first run this auto-generates `deploy/.env` with a strong random
`ZTP_ADMIN_TOKEN` (no insecure default — the server refuses to start
otherwise) and brings up:

- `caddy` — TLS terminator on `https://localhost:8443`. Serves the **SPA at
  `/`** and proxies `/v1/*` to the backend, so a single origin handles both.
  Local dev uses Caddy's internal CA; switch to a real domain + Let's Encrypt
  by editing `ZTP_SITE_ADDRESS` and `ZTP_TLS_EMAIL` in `deploy/.env`. The
  rest of the stack does not change between dev and production.
- `ztp-server` — listens **only on the internal docker network** with
  persistent SQLite + a generated signing key in `deploy/data/`. Not exposed
  to the host directly, so the admin token never leaves the encrypted hop.
- the Svelte SPA dev server on <http://localhost:5175> (HMR convenience —
  proxies `/v1/*` to the server over the internal docker network),
- `ztp-device-demo` — alpine container running the **Go** agent, connecting
  via HTTPS to Caddy (`-ca` mounted from the Caddy local CA volume),
- `ztp-device-shell` — alpine container running the **POSIX shell** agent
  over the same TLS path.

Both demo devices show up under <https://localhost:8443/pending> on first
contact; approve them and watch each apply the bundle. To inspect just one:

```sh
just logs device-shell    # or: device, server, web, caddy
```

Spin up an extra fresh device that will end up in the **Pending** tab:

```sh
just device lab-device-01
```

### Deploying publicly

Edit `deploy/.env`:

```
ZTP_SITE_ADDRESS=ztp.example.com
ZTP_TLS_EMAIL=ops@example.com
```

Point an A record at the host, open 80/443 (Let's Encrypt needs both for
the HTTP-01 challenge), and `just up -d`. Caddy fetches a real cert
automatically. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the
backup / DR strategy (signing key offline, SQLite via Litestream).

### Profile secrets (SOPS-age)

Profile files like `deploy/profiles.d/default.yaml` can be encrypted at rest
using the [SOPS](https://github.com/getsops/sops) format with
[age](https://age-encryption.org/) recipients. The server has a built-in
decoder, so **`sops` is not required at runtime** and `ztpctl` ships
matching seal/edit commands so operators don't need it on their workstation
either.

On `just up` the server auto-generates an X25519 age identity at
`deploy/data/age.key` (mode 0600, persisted via the data volume) and a
sidecar pubkey at `deploy/data/age.key.pub`. After that the workflow is:

```sh
# 1. Seal common secret-shaped keys in place. Defaults to encrypting
#    `password`, `bootstrap_token`, anything matching `*token*` / `*secret*`.
just secrets-seal

# 2. Edit a sealed file — opens $EDITOR on the decrypted plaintext and
#    re-encrypts on save using the same rules and recipients.
just secrets-edit

# 3. Print the decrypted plaintext (gated by --yes-show-secrets).
just secrets-reveal
```

Pure `${VAR}` / `${VAR:-default}` placeholders are left in plaintext on
purpose — the placeholder string itself isn't secret, the runtime env var
is. Mixed strings (`prefix-${VAR}-suffix`) and literal values still get
sealed.

Files are byte-compatible with upstream `sops`, so an operator who already
runs `sops -e -i` / `sops profile.yaml` can use either tool. For
multi-operator deployments add extra public keys to `age_recipients:` in
`deploy/config/ztp-server.yaml`. See
[examples/profiles.d/README.md](examples/profiles.d/README.md) for the full
reference.

## Quick start (native)

```sh
just build
export ZTP_ADMIN_TOKEN=$(openssl rand -hex 32)
./bin/ztp-server -config examples/ztp-server.yaml -v &
PUB=$(./bin/ztp-server -config examples/ztp-server.yaml -print-pubkey)
./bin/ztpctl allowlist add my-device
./bin/ztp-agent \
    -server http://localhost:8080 \
    -server-pubkey "$PUB" \
    -device-id my-device \
    -appliers ./scripts/appliers \
    -insecure -v
```

To discover the server via mDNS instead of `-server`:

```sh
./bin/ztp-agent -mdns -appliers ./scripts/appliers -insecure -v
```

For the docker-compose stack, the in-container mDNS publisher can't escape
Docker's bridge network (UDP 5353 multicast doesn't traverse it). To make
the LAN discovery actually reach devices:

| Host                | Command                       | Notes                                                               |
| ------------------- | ----------------------------- | ------------------------------------------------------------------- |
| Linux / AWS EC2     | `just mdns-publish`           | Starts a `network_mode: host` sidecar (`ztp-mdns`) in the `mdns` profile. |
| macOS + colima      | `just mdns-publish-macos`     | colima's host network is the VM, not the Mac LAN; this script registers with the Mac's `mDNSResponder` via `dns-sd`. |
| Browse from any LAN | `just mdns-discover`          | Uses `dns-sd -B` or `avahi-browse`.                                 |

Both publishers fetch the server's pubkey from `/v1/server-info` and put it
in the TXT record, so a discovering agent can verify signatures without any
out-of-band configuration.

To request an end-to-end-encrypted bundle (recommended over BLE relays):

```sh
./bin/ztp-agent -encrypt -server http://localhost:8080 -server-pubkey "$PUB" ...
```

## POSIX shell agent (no Go binary)

For tiny / read-only / busybox-only images, there is a pure POSIX shell agent
at `scripts/agent/ztp-agent.sh`. It speaks to the server with
`Accept: text/plain`, so it never has to parse JSON — every response is
line-oriented `key=value`, the bundle is delivered as a separately-signed text
manifest with one `module=<type> <base64-payload>` line per module.

**Required tools on the device**: `curl`, `openssl` (with Ed25519 — OpenSSL
1.1.1+ / LibreSSL 3.7+), `base64`, `awk`, `sed`. **Not** required: `jq`, Go
runtime, anything else.

```sh
# Trust the server (one-off):
PUB=$(./bin/ztp-server -config examples/ztp-server.yaml -print-pubkey)

# Drop-in applier — same dispatch convention as the Go agent: filename matches
# the module type, the payload is fed on stdin.
sudo install -d /etc/ztp/appliers.d
sudo tee /etc/ztp/appliers.d/files.v2.sh >/dev/null <<'EOF'
#!/bin/sh
# Receives the module payload (INI-formatted) on stdin.
# Parse with the helpers under scripts/appliers/lib/ini.sh, or sed/awk —
# the canonical references live alongside this stub at scripts/appliers/.
cat >/var/lib/ztp/last-files.ini
echo "files.v2 applied"
EOF
sudo chmod +x /etc/ztp/appliers.d/files.v2.sh

# Run the agent. First contact is queued for manual approval; once an operator
# clicks Approve in the SPA, re-run and the bundle is applied.
ZTP_SERVER=http://localhost:8080 \
ZTP_SERVER_PUBKEY="$PUB" \
ZTP_DEVICE_ID="$(cat /etc/machine-id)" \
ZTP_IDENTITY_KEY=/var/lib/ztp/identity.pem \
ZTP_APPLIERS_DIR=/etc/ztp/appliers.d \
sh scripts/agent/ztp-agent.sh
```

Optional environment:

| Variable | Purpose |
|---|---|
| `ZTP_TOKEN` | Bootstrap token to claim auto-trust on first contact. |
| `ZTP_CA` | Pin a PEM CA cert for the server's TLS chain. |
| `ZTP_DEVICE_ID` | Override `/etc/machine-id` / `hostname`. |

The script also ships in the `ztp-agent:dev` Docker image at
`/usr/local/bin/ztp-agent.sh` for local experiments.

### In Docker Compose

A second device service, `device-shell`, runs the shell agent end-to-end
inside the demo stack. It builds the dedicated `agent-shell` Dockerfile stage
(alpine + curl/openssl/jq, busybox awk/sed) — **no Go binary in the image**.

```sh
just up                                           # both Go and shell devices start
docker compose -f deploy/docker-compose.yaml \
    logs -f device-shell                          # watch its enrollment loop
```

Spawn an extra **fresh** shell-only device against the running stack:

```sh
just device-shell shop-floor-pi-7                 # uses --rm + a unique device id
```

Override the device id (it is otherwise `shell-device-1`):

```sh
ZTP_DEVICE_ID_SHELL=shop-floor-pi-7 just up
```

The shell device persists its identity key in the `device_shell_identity`
named volume, so restarts re-enroll as the **same** device (no stale pending
entries) — exactly like the Go device.

## BLE relay (opt-in)

Build the agent with the BLE transport tag — requires BlueZ on Linux,
CoreBluetooth on macOS:

```sh
just agent-ble
```

The relay (gateway) and peripheral (device) helpers live in
`internal/transport/ble`. See the package doc for the GATT layout.

## Deployment

The Quick start sections above show the demo stack. For a side-by-side of
the three real deployment shapes — native (with mDNS), minimal Docker
Compose (with and without HTTPS), and production behind Caddy + Let's
Encrypt — see [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for a full walkthrough of the
composable interfaces (`Verifier`, `PayloadProvider`, `Applier`, `Transport`,
`Store`, `IdentityProvider`).
