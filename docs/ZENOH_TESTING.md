# Testing Zenoh Discovery Locally

This guide walks through an end-to-end local test of the Zenoh-based seamless
discovery feature using infrastructure that is already part of the project.

**Prerequisites** — things you already have if you have been working with this
project:

- Go ≥ 1.21
- `just`
- Docker (for the ZTP server stack if you want the full UI; optional for a
  quick headless test)

The only additional thing needed is `zenoh-c`, the C library that the
`zenoh-go` CGo binding links against.  No separate Zenoh router process is
needed — the ZTP server can act as the router itself.

---

## 1 — Install zenoh-c (one-time)

`zenoh-c` provides the shared library required by the `-tags zenoh` build.
Install it from the official GitHub releases; no package manager tap is needed.

### macOS (Apple Silicon or Intel)

```sh
# Pick the correct asset for your CPU:
#   macOS Apple Silicon → aarch64-apple-darwin
#   macOS Intel        → x86_64-apple-darwin
ARCH=aarch64-apple-darwin   # or x86_64-apple-darwin
VERSION=1.9.0
cd /tmp
curl -fsSL "https://github.com/eclipse-zenoh/zenoh-c/releases/download/${VERSION}/zenoh-c-${VERSION}-${ARCH}-standalone.zip" \
  -o zenoh-c.zip
unzip -q zenoh-c.zip
cp -R include/* /usr/local/include/
cp -R lib/*     /usr/local/lib/
# Fix the dylib's install name — the release asset has a CI build path baked in.
install_name_tool -id /usr/local/lib/libzenohc.dylib /usr/local/lib/libzenohc.dylib
```

> **Important**: use the `*-standalone.zip` asset, not the plain tarball.
> The standalone zip is built with `ZENOHC_BUILD_WITH_UNSTABLE_API=ON` which
> compiles in the `zc_*` symbols that `zenoh-go` requires.  The plain tarball
> omits them and causes a CGo build error.

### Linux (Debian/Ubuntu)

```sh
# Pick the correct asset for your CPU:
#   Linux x86_64 → x86_64-unknown-linux-gnu
#   Linux arm64  → aarch64-unknown-linux-gnu
ARCH=x86_64-unknown-linux-gnu
VERSION=1.9.0
cd /tmp
curl -fsSL "https://github.com/eclipse-zenoh/zenoh-c/releases/download/${VERSION}/zenoh-c-${VERSION}-${ARCH}-standalone.zip" \
  -o zenoh-c.zip
unzip -q zenoh-c.zip
sudo cp -R include/* /usr/local/include/
sudo cp -R lib/*     /usr/local/lib/
sudo ldconfig
```

> Same `*-standalone.zip` requirement as macOS above.

---

## 2 — Build with the zenoh tag

Use the provided `just` recipes, which set `CGO_LDFLAGS` correctly to avoid a
macOS dylib install-name issue in the release asset:

```sh
just agent-zenoh   # → bin/ztp-agent-zenoh
just server-zenoh  # → bin/ztp-server-zenoh
```

Both binaries are written to `bin/` and do not replace the standard ones.

---

## 3 — Run the ZTP server natively (simplest path)

The example config (`examples/ztp-server.yaml`) already has `zenoh.enabled: true`
and `listen_addr: tcp/0.0.0.0:7447` set.  Just run:

```sh
just run-server-zenoh
```

Expected startup log:

```
level=INFO msg="zenoh server: starting in router mode" listen=tcp/0.0.0.0:7447
level=INFO msg="zenoh server: discovery subscriber active" listen=tcp/0.0.0.0:7447 ...
```

The server listens on `:8080` for HTTP and `:7447` for Zenoh.
No Docker, no separate Zenoh router process — the ZTP server is both.

---

## 4 — Run the agent with zenoh discovery

In a second terminal:

```sh
just run-agent-zenoh
```

Optional: pass a device ID as the first argument to run multiple simultaneous agents:

```sh
just run-agent-zenoh my-device-2
```

The recipe redirects identity key and sentinel file to `/tmp/ztp-dev/` so no root
access is needed, and passes `--force` so you can re-run enrollment without
deleting state manually.

The agent prints something like:

```
level=INFO msg="zenoh discovery: publishing beacon" device=dev-device-1 router=tcp/localhost:7447
```

It then waits — periodically re-publishing the beacon — until an operator
approves the device.

---

## 5 — Approve the device

The device now appears in the "Pending" list.  Approve it one of two ways.

### Via curl (admin API)

The example config has no `admin_token` set, so the server reads it from the
`ZTP_ADMIN_TOKEN` env var (set by `just init` into `deploy/.env`).  For a
quick local test without the Docker stack, export any token before starting the
server and reuse it here:

```sh
export ZTP_ADMIN_TOKEN=dev-token-change-me
# then start the server: just run-server-zenoh

SERVER=http://localhost:8080

# List pending devices
curl -s -H "Authorization: Bearer $ZTP_ADMIN_TOKEN" "$SERVER/v1/admin/pending" | jq .

# Approve by ID (copy the id field from the listing above)
PENDING_ID=<paste-id-here>
curl -s -X POST \
  -H "Authorization: Bearer $ZTP_ADMIN_TOKEN" \
  "$SERVER/v1/admin/pending/$PENDING_ID/approve"
```

### Via the SPA (full stack)

If you prefer the browser UI, bring up the full Docker stack first (`just up`)
then enable zenoh on the deployed server config as described in
[Using the Docker stack](#using-the-docker-stack) below, and navigate to
`https://localhost:8443` → **Pending**.

---

## 6 — Watch enrollment complete

After approval:

1. The server publishes an `ApprovalPayload` to `ztp/discovery/approve/<device-id>`.
2. The agent receives the payload, extracts the server HTTPS URL, and proceeds
   with the standard enrollment call.
3. The agent logs should end with something like:

   ```
   level=INFO msg="zenoh discovery: server approved, enrolling via HTTP" server_url=http://localhost:8080
   level=INFO msg="enrollment complete"
   ```

4. The device moves from Pending to the **Devices** list.

---

## Cleanup

```sh
rm -rf /tmp/ztp-dev   # agent identity keys and sentinel files
```

---

## Using the Docker stack

If you want the full SPA UI during testing, run the normal Docker stack and
rebuild the server image with the zenoh tag:

```sh
# Rebuild the server image with -tags zenoh
DOCKER_BUILDKIT=1 docker compose -f deploy/docker-compose.yaml build \
  --build-arg GOFLAGS="-tags=zenoh" server

just up
```

Then add the zenoh block to `deploy/config/ztp-server.yaml`:

```yaml
zenoh:
  enabled: true
  listen_addr: "tcp/0.0.0.0:7447"
```

Expose port 7447 by adding it to the server service in
`deploy/docker-compose.yaml`:

```yaml
services:
  server:
    ports:
      - "7447:7447"
```

Restart the server:

```sh
docker compose -f deploy/docker-compose.yaml restart server
```

Agents on the host or LAN connect with `--zenoh-router tcp/localhost:7447`.

---

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `error: transport zenoh not supported` at agent startup | Binary was built without `-tags zenoh` |
| `zenoh: open session: ...` error | zenoh-c library not found; check `LD_LIBRARY_PATH` / `DYLD_LIBRARY_PATH` |
| `could not determine what C.zc_get_last_error refers to` | Wrong zenoh-c asset — reinstall using the `*-standalone.zip` (see step 1) |
| `dyld: Library not loaded: /Users/runner/work/...` (abort) | CI path baked in dylib — run `install_name_tool -id /usr/local/lib/libzenohc.dylib /usr/local/lib/libzenohc.dylib` then rebuild with `just agent-zenoh` / `just server-zenoh` |
| Device never appears in Pending | Server not built with `-tags zenoh`; `zenoh.enabled: false`; wrong port |
| Approval published but agent does not react | Subscription race (rare); agent re-publishes every 30 s, wait for next cycle |
| Server container not reached by agents | Ensure port 7447 is exposed in docker-compose; use `tcp/host.docker.internal:7447` from host |
