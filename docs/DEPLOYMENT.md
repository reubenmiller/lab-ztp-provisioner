# Deployment guide

`ztp-server` is the same single binary in every scenario. What changes is
where it listens, how TLS is terminated, where state lives, and whether
mDNS advertisement is direct or via a host-network sidecar. This guide
walks through three setups, ordered by complexity:

1. [Native (laptop / single host)](#1-native-laptop--single-host) — fastest
   to bring up, includes mDNS LAN advertisement.
2. [Minimal Docker Compose (no Caddy)](#2-minimal-docker-compose-no-caddy) —
   containerised, with optional self-signed TLS for plain HTTPS without a
   reverse proxy.
3. [Production (Caddy + Let's Encrypt)](#3-production-caddy--lets-encrypt) —
   the full `deploy/docker-compose.yaml` stack on a public hostname.

Across all three, `ZTP_ADMIN_TOKEN` is **mandatory** — the server refuses
to start without one. There is no insecure default.

---

## 1. Native (laptop / single host)

Run the binary directly. State lives where the config points; mDNS is
published from the host network stack with no special workaround. This is
how you'd run the server on a workshop laptop, a Raspberry Pi gateway, or
an EC2 instance without containers.

### 1a. With mDNS LAN discovery

`mdns.enabled: true` in the YAML makes the server publish `_ztp._tcp` on
the LAN itself — agents that find it via `-mdns` will connect with no
preconfigured server URL. Native processes can do this directly because
they share the host's network namespace; the [Docker workarounds](#mdns-and-docker-bridge-networking)
under section 2 do not apply.

```sh
# Build once.
just build

# Generate a strong token (or set it in your shell rc).
export ZTP_ADMIN_TOKEN=$(openssl rand -hex 32)

# Copy the example config, enable mDNS, point store + keys at a writable dir.
mkdir -p ~/.ztp/data ~/.ztp/profiles.d
cp examples/ztp-server.yaml ~/.ztp/ztp-server.yaml

cat >>~/.ztp/ztp-server.yaml <<'EOF'

# Persisted state — survive restarts so devices keep trusting us.
signing_key_file: "~/.ztp/data/signing.key"
age_key_file:     "~/.ztp/data/age.key"
profiles_dir:     "~/.ztp/profiles.d"

store:
  driver: sqlite
  dsn:    ~/.ztp/data/ztp.db

# Advertise on the LAN. The host *must* be on a network where multicast
# UDP 5353 isn't filtered (most home / office LANs are fine; some
# corporate networks block mDNS).
mdns:
  enabled: true
  service: _ztp._tcp
  port:    8080
EOF

./bin/ztp-server -config ~/.ztp/ztp-server.yaml -v
```

Confirm it's advertised:

```sh
just mdns-discover    # uses dns-sd -B (macOS) or avahi-browse (Linux)
```

A nearby device picks it up automatically:

```sh
./bin/ztp-agent -mdns -appliers ./scripts/appliers -insecure -v
```

The SPA is at <http://localhost:8080/>. The bearer token is whatever you
exported as `ZTP_ADMIN_TOKEN`.

> **Note:** plain HTTP is fine on loopback / a trusted LAN, but the
> bearer token is the only auth — don't expose `:8080` to a hostile
> network without TLS. Promote to TLS with `tls.mode: selfsigned` (next
> section) or front it with Caddy / nginx.

### 1b. With self-signed TLS (no reverse proxy)

For a single-host deployment that needs HTTPS without standing up Caddy,
the server can mint and cache its own cert:

```yaml
# ~/.ztp/ztp-server.yaml
listen: ":8443"
tls:
  mode: selfsigned
  hostnames:
    - ztp.local           # whatever hostname devices will use
    - 192.168.1.42        # any LAN IP they'll connect to
```

The cert is generated on first start and cached under
`paths.TLSCacheDir()` (`~/.local/share/ztp/tls/` on Linux,
`~/Library/Application Support/ztp/tls/` on macOS). Devices need
`-ca <pem>` pointing at it, or `-insecure` for testing.

### 1c. Native ztp-app (desktop)

`bin/ztp-app` is the same engine inside a Wails window. By default it
runs on loopback with an in-memory store (every launch is fresh). Two
flags promote it to a real LAN listener:

```sh
just app-build
./bin/ztp-app -listen :8080 -mdns       # publishes _ztp._tcp from the laptop
./bin/ztp-app -config deploy/config/ztp-app.yaml   # reuse the docker stack's persistent state
```

This is the easiest way to run a small ZTP server *without writing a
config file at all* — open the app, click around, devices on the LAN
discover it.

---

## 2. Minimal Docker Compose (no Caddy)

A container, no reverse proxy. Useful for ops that already have an
external load balancer / TLS terminator, or for a quick "everything in
one VM" deployment without the Caddy + SPA + mDNS sidecar from
`deploy/docker-compose.yaml`.

Save this as `docker-compose.minimal.yaml`:

```yaml
services:
  server:
    build:
      context: .
      dockerfile: Dockerfile
      target: server
    image: ztp-server:dev
    container_name: ztp-server
    ports:
      - "8080:8080"          # plain HTTP; expose ONLY behind a trusted edge
    volumes:
      - ./data:/var/lib/ztp
      - ./config/ztp-server.yaml:/etc/ztp/ztp-server.yaml:ro
      - ./profiles.d:/etc/ztp/profiles.d:ro
    environment:
      - ZTP_ADMIN_TOKEN     # passed through from your shell or .env file
```

Bring up with a config that does NOT enable mDNS (Docker bridge
networking can't multicast — see below) and uses persistent SQLite:

```yaml
# config/ztp-server.yaml
listen: ":8080"
signing_key_file: "/var/lib/ztp/signing.key"
age_key_file:     "/var/lib/ztp/age.key"
store:
  driver: sqlite
  dsn:    /var/lib/ztp/ztp.db
profiles_dir:     "/etc/ztp/profiles.d"
default_profile:  "default"
verifiers: [allowlist, bootstrap_token, known_keypair]
```

Then:

```sh
mkdir -p data profiles.d config
# put the YAML above at config/ztp-server.yaml
export ZTP_ADMIN_TOKEN=$(openssl rand -hex 32)
docker compose -f docker-compose.minimal.yaml up -d
```

Devices reach it at `http://<host>:8080`. The embedded SPA is served at
`/`; `/v1/*` is the API. There is no separate web container — the
`ztp-server` binary embeds the built SPA assets.

### 2a. Adding HTTPS without Caddy

Two paths, both keep the stack to the single `ztp-server` container.

**Self-signed (cert managed by the server).** Mount a writable volume
for the cert cache and switch the mode:

```yaml
# config/ztp-server.yaml additions
listen: ":8443"
tls:
  mode: selfsigned
  hostnames:
    - ztp.example.local
    - 10.0.0.50
```

```yaml
# docker-compose.minimal.yaml additions
    ports:
      - "8443:8443"
    volumes:
      - ./tls-cache:/root/.local/share/ztp/tls   # cert + key persisted here
```

Devices use `-ca ./tls-cache/selfsigned.crt` to verify, or `-insecure`
to skip verification (testing only).

**Operator-managed cert (mTLS-friendly, BYO PKI).** Mount the PEM files
in and point the server at them:

```yaml
# config/ztp-server.yaml
tls:
  mode: cert
  cert: /etc/ztp/tls/server.crt
  key:  /etc/ztp/tls/server.key
```

```yaml
# compose
    volumes:
      - ./tls:/etc/ztp/tls:ro
```

This is the right shape if you already issue certs from an internal CA
and want device-side `-ca` pinning to your own root.

### mDNS and Docker bridge networking

mDNS is multicast UDP 5353. Docker's default bridge does not forward
multicast packets between the container and the host LAN, so a
container that calls `mdns.Publish()` will publish — but only inside
its own bridge namespace, which devices on the physical LAN cannot see.

There are two ways out:

- Run `ztp-server` (or just the bundled `cmd/ztp-mdns-publish` sidecar)
  in `network_mode: host` so it shares the host's network namespace.
  This is what `just mdns-publish` does (it adds the `mdns` service
  from the production compose with the `mdns` profile enabled). It only
  works on Linux hosts — Docker Desktop on macOS / Windows runs Docker
  in a VM, and host networking shares the *VM's* network, not the
  Mac's.
- On macOS / Windows / Docker-Desktop hosts, run the publisher
  natively. `just mdns-publish-macos` registers the service via the
  Mac's `mDNSResponder` so it's seen on the real LAN.

The minimal compose above intentionally does not enable mDNS — devices
either connect via an explicit `-server <url>` flag, or you publish
out-of-band.

---

## 3. Production (Caddy + Let's Encrypt)

This is the canonical `deploy/docker-compose.yaml` stack — Caddy in
front for TLS termination, the SPA served at `/`, the API at `/v1/*`,
the server unreachable from the host except via Caddy. Same compose
file works locally and in production; only `deploy/.env` changes.

```sh
# 1. Bootstrap (auto-generates deploy/.env with a strong ZTP_ADMIN_TOKEN
#    on first run; you SHOULD copy the value to your password manager).
just up
```

This brings up:

| service          | role                                                      |
| ---------------- | --------------------------------------------------------- |
| `caddy`          | TLS terminator on `${ZTP_HTTPS_PORT:-8443}`, serves SPA + API. |
| `ztp-server`     | Engine. **Not** published to the host — Caddy is its only ingress. |
| `web`            | Vite dev server for HMR (production drops this — see below). |
| `ztp-device-demo` and `ztp-device-shell` | end-to-end test devices. |

### 3a. Going public

Edit `deploy/.env`:

```ini
ZTP_SITE_ADDRESS=ztp.example.com
ZTP_TLS_EMAIL=ops@example.com         # used for Let's Encrypt registration
ZTP_HTTPS_PORT=443                    # standard HTTPS — Let's Encrypt needs :80 too
ZTP_CADDYFILE=./Caddyfile             # not the .mkcert variant
```

Open inbound 80 + 443 (Let's Encrypt's HTTP-01 challenge needs both),
point an A record at the host, then:

```sh
just up -d
```

Caddy fetches a real Let's Encrypt cert automatically. No code or
config change in `ztp-server` itself — only the env vars Caddy reads.

### 3b. Production hardening checklist

- **Lock `/v1/admin/*` behind your VPN / IP allowlist** in addition to
  the bearer token. The Caddyfile ships a commented-out `@admin` block
  that does this; uncomment and adapt.
- **Rip out the `web` service.** It's a Vite dev server — fine for
  local HMR, not what you want exposed in production. The SPA is
  embedded into the `ztp-server` binary; Caddy can serve it directly
  from the server's `/` route, or you can drop a `file_server` rooted
  at `web/build/` (see comment in `deploy/Caddyfile`).
- **Move SQLite to durable storage.** `./data` is a host-bind mount;
  back it up alongside your other DBs, or replace with Litestream
  streaming to S3 (see [docs/ARCHITECTURE.md](ARCHITECTURE.md) for the
  DR sketch).
- **Rotate `ZTP_ADMIN_TOKEN`.** It's auto-generated on first `just up`,
  but rotation is a single edit in `deploy/.env` + `docker compose
  restart server`.
- **Take the signing key offline.** The auto-generated key under
  `deploy/data/signing.key` is fine for local dev; production should
  generate it on an offline machine, copy in only the encrypted form
  (or use `signing_key_file:` pointing at a tmpfs-mounted secret).
- **Enable HSTS.** Already in the production `Caddyfile`; verify with
  `curl -I https://ztp.example.com/`.

### 3c. Production with on-prem mDNS

If your devices are on the same LAN as the production host (e.g.
factory floor with a local server), enable the `mdns` compose profile
so the host-network sidecar advertises the public Caddy address:

```sh
just mdns-publish     # docker compose --profile mdns up -d ztp-mdns
```

The sidecar reads `ZTP_SITE_ADDRESS` + `ZTP_HTTPS_PORT` from the
environment and publishes `_ztp._tcp` with a SRV record pointing at
that public face — devices use `-mdns` and reach Caddy directly with a
trusted Let's Encrypt cert.

---

## At a glance

| Scenario                  | TLS                            | State                  | mDNS                            | Use when |
| ------------------------- | ------------------------------ | ---------------------- | ------------------------------- | -------- |
| Native (1a)               | none (loopback / trusted LAN)  | wherever you point it  | yes — direct from host          | laptops, single-host gateways, demos |
| Native + selfsigned (1b)  | self-signed, server-managed    | wherever you point it  | yes                             | small fleets, no PKI yet |
| Native ztp-app (1c)       | none (loopback)                | in-memory or shared with compose | yes (`-mdns`)        | trying things out / desktop UX |
| Minimal compose (2)       | none — exposes `:8080`         | bind-mounted SQLite    | no (Docker bridge)              | sits behind your own LB / VPN |
| Minimal + selfsigned (2a) | self-signed, server-managed    | bind-mounted SQLite    | no (use host sidecar if needed) | small prod, no Caddy budget |
| Minimal + cert (2a alt)   | operator-managed PEM           | bind-mounted SQLite    | no                              | already have a CA / mTLS |
| Production compose (3)    | Caddy + Let's Encrypt          | persisted volumes      | optional, host-network sidecar  | public deploy, real domain |
