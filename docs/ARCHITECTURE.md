# Architecture

This document describes the composable interfaces that make up the ZTP
system. Each interface has a default implementation that ships with the
binary and a clean extension point so operators can plug in their own.

## Server side

```
        ┌───────────────────────────────────────────────────────────┐
EnrollRequest                                                       │
  ──▶  Transport ──▶ Engine ──▶ Verifier chain ──▶ Decision         │
                       │                                            │
                       ├───── Trust ───────▶ PayloadRegistry ──▶ signed bundle
                       ├───── Pending ─────▶ Store.CreatePending  ┐
                       └───── Reject  ─────▶ Audit log + 4xx      │
                                                                  ▼
                                          operator approves via admin API
                                          ⇒ device upserted, next contact
                                            passes the known_keypair Verifier
```

### `Transport` — accepts EnrollRequests
Default: HTTPS server (`internal/server/api`). Future: mDNS-discovered LAN
listener, BLE-relay receiver. The Engine never depends on transport details.

### `Verifier` — chain of small decisions
Each `Verifier` returns `Trust`, `Pending`, or `Reject`. The chain runs in
order; the first non-`Pending` verdict wins. If every verifier returns
`Pending` the request lands in the manual-approval queue.

Built-ins:
- `Allowlist` — pre-registered device IDs, MACs, or serials
- `BootstrapToken` — short-lived hashed tokens (single- or limited-use)
- `KnownKeypair` — TOFU: device's pubkey already pinned to a Device row
- `TPMAttestation` (stub) — replace with a real `go-tpm` implementation
- `mTLS` (planned) — when client cert chains to a configured CA

### `PayloadProvider` — composable per-module producers
Each provider emits zero or more typed `Module`s. Providers are toggled
independently via config. Per-device overrides live in `Device.Overrides` and
let providers return device-specific values (e.g. a fresh c8y OTP).

Built-ins (all v2 / INI payloads — the v1 / JSON variants were
removed; older agents shipping only `*.v1.sh` appliers must be upgraded):
- `wifi.v2` — `[network]` sections: `ssid`, `password`, `key_mgmt`, `hidden`, `priority`
- `ssh.authorized_keys.v2` — `[ssh]` section with `user=` plus repeated `key=` lines
- `c8y.v2` — `[c8y]` section: `url`, `tenant`, `external_id`, `one_time_password`
- `files.v2` — `[file]` sections: `path`, `mode`, `owner`, `contents_b64`
- `hook.v2` — `[hook]` section: `interpreter`, `script_b64` (off by default)
- `passwd.v2` — `[user]` sections, see `internal/server/payload/passwd.go`

### `Store` — persistence
Default: in-memory (good for tests and single-binary local LAN). The
interface is small (devices, pending, allowlist, tokens, audit, nonces) so
swapping for SQLite or Postgres is straightforward.

## Device side

```
Identity (Ed25519) ──▶ build EnrollRequest ──▶ POST /v1/enroll
                                                        │
                                                        ▼
                                       verify bundle signature with server pubkey
                                                        │
                                                        ▼
                                              Dispatcher (per-module)
                                              │      │       │
                                            wifi.v2  ssh.v2  c8y.v2
                                              │      │       │
                                  /etc/ztp/appliers.d/<type>.sh   (drop-in, wins)
                                  built-in Go handler             (fallback)
                                  none                            ⇒ skipped, not fatal
```

Drop-in scripts receive the module's payload as JSON on stdin and may write
arbitrary side effects. Unknown module types are recorded as `skipped` in
the per-module result; new server versions can therefore add modules without
breaking older agents.

## Bluetooth provisioning (planned)

For devices that cannot reach the server directly:
1. Device runs `ztp-agent` in BLE-peripheral mode, advertising a `ztp` GATT
   service (`enroll-request`, `enroll-response`, `status` characteristics).
2. A relay (`ztp-agent gateway`, or a phone app) connects, reads the request,
   POSTs it to the server over HTTPS, and writes the response back.
3. The bundle is end-to-end encrypted with X25519 + ChaCha20-Poly1305 to the
   device's ephemeral key (`EnrollRequest.EphemeralX25519`), so the relay is
   untrusted.

## Provisioning profiles

A **profile** is the named bundle of payload-provider configuration that the
server hands to a device at enrollment. Profiles replace the legacy single
top-level `payload:` block; each device is assigned exactly one.

**Two storage backends, merged at lookup time:**

- **File-backed** (`profiles_dir`, default `/etc/ztp/profiles.d/`): one YAML
  file per profile, git-managed. Read-only via the admin API. May be
  encrypted with [SOPS](https://github.com/getsops/sops) — the server
  detects a top-level `sops:` block and shells out to the local `sops` CLI
  to decrypt at load time. SOPS key material is resolved by `sops` itself
  via the standard `SOPS_AGE_KEY_FILE`, `SOPS_KMS_ARN`, etc. env vars; the
  ZTP server never sees plaintext key material.
- **DB-backed**: created/edited via the admin UI; stored alongside devices
  and tokens in the same `Store`. Editable.

On name collision the **file profile wins** so a git-managed profile cannot
be silently overridden from the UI.

**Per-device resolution precedence** (first hit wins):

1. `Device.Overrides["_profile"]` — operator-set override via
   `PATCH /v1/admin/devices/{id}` `{"profile": "..."}`.
2. `Device.ProfileName` — sticky from a prior enrollment. Once a device has
   been provisioned with profile X, the same profile is reused on future
   enrollments even if facts change.
3. Verifier hint — `AllowlistEntry.Profile` or `BootstrapToken.Profile`,
   surfaced in `trust.Result.Profile`.
4. Selector match against `DeviceFacts` (model regex, hostname regex, MAC
   OUI list) in priority-desc, name-asc order.
5. **Device-supplied advisory hint** — `EnrollRequest.Metadata["profile"]`,
   sent by the agent via `--profile <name>` (Go, Rust) or `ZTP_PROFILE=<name>`
   (shell). Treated as a hint only because it is unauthenticated at first
   contact: any operator-side step above wins, and an unknown name falls
   through rather than failing. The audit log records `requested=<name>
   requested_honoured=<bool>` whenever the device sent a hint, so an operator
   can spot devices asking for a profile they didn't get.
6. `default_profile` from `ztp-server.yaml`.
7. The literal profile named `default`.

If none match, enrollment is **rejected** rather than silently issued an
empty bundle.

**Secret protection at rest:**

- `${VAR}` / `${VAR:-default}` interpolation is run on every string leaf
  after SOPS decryption, so even encrypted profiles can pull last-mile
  secrets from the environment.
- Fields tagged `ztp:"sensitive"` (wifi password, c8y `static_token`, hook
  script body, file `contents`/`base64`) are replaced with `<redacted>` in
  every `GET /v1/admin/profiles/*` response.
- The audit log records the profile name + source on every accept/reject;
  it never records secret values.

**Reload without downtime:** `kill -HUP <pid>` re-reads `profiles_dir` and
re-resolves c8y issuers. On parse error the previously loaded set stays in
place. `POST /v1/admin/profiles/reload` triggers the same path from the
admin API.

## Security notes

- All requests carry a fresh nonce (replay-protected for `nonce_ttl`).
- Timestamps must be within `clock_skew` of server time (default: 5 minutes).
- Bundles are always Ed25519-signed; agents reject unsigned bundles.
- Bootstrap tokens are stored only as SHA-256 hashes.
- The manual-approval flow surfaces raw `DeviceFacts` + a 12-char public-key
  fingerprint to the operator UI so a human can compare with what's printed
  on the device label.

## Clock skew handling

New devices frequently have no NTP access before provisioning.  This is
especially common in the BLE provisioning path, where the device has no
network at all until `ztp-agent` delivers WiFi credentials.  A factory-reset
or first-boot clock defaults to the Unix epoch (1970), which produces a skew
of tens of thousands of hours and would permanently lock out enrollment.

### How it works

Every response from the ZTP server (success *and* rejection) includes a
`server_time` field in the JSON body:

```json
{ "status": "rejected", "reason": "request timestamp out of allowed skew (345h…)",
  "server_time": "2026-04-27T14:32:01Z" }
```

The agent uses this value to compute a **clock offset** — the difference
between the server's wall-clock and its own — and stores it in memory as
`Config.ClockOffset` (Go) / `Config.clock_offset` (Rust).  On the *next*
request the agent adds the offset to `time.Now()` / `Utc::now()` before
placing the timestamp in the envelope.  Up to and including bundle
verification the **system clock is left untouched**; only the value written
into the outgoing request payload changes.

After the bundle's signature has been verified — and only then — the agent
applies the bundle's signed `issued_at` timestamp to the host's real-time
clock (`CLOCK_REALTIME` via `settimeofday(2)`).  This single step happens in
the shared post-verify code path so it covers both transports identically;
no transport-specific logic is involved.  It exists because the offset
mechanism above only fixes the *outgoing enrollment request* — once
appliers run, `tedge cert download c8y` and any other downstream TLS client
re-read `time.Now()` against external certificates, and a stale OS clock
will fail their `NotBefore` checks even though enrollment succeeded.

The behaviour is governed by an agent-side policy (`--system-clock`):

| Policy | Forward jump | Backward jump | Default? |
|--------|--------------|---------------|----------|
| `auto` | yes, when `> 60 s` behind | refused | ✓ |
| `off`  | never | never | — |
| `always` | yes, when `> 60 s` | yes, when `> 60 s` | — |

`auto` is **forward-only** because rolling the wall-clock backwards breaks
file mtimes, audit logs, and cron schedules in subtle ways.  Devices whose
clock is *ahead* of the server (rare) stay ahead.  The 60-second threshold
is hard-coded; small NTP-class drifts are not interesting and would only
add log noise.

Adjustment requires `CAP_SYS_TIME` (typically root).  When the capability
is missing, `settimeofday` returns `EPERM`; the agent logs a warning and
continues so a slightly-skewed device that does not actually need the fix
can still finish provisioning.

Trust model: `bundle.IssuedAt` lives inside the Ed25519-signed payload and
is verified against the pinned `ServerPubKey` before this step runs, so it
inherits the same authenticity as the rest of the bundle regardless of
whether the bundle arrived over HTTPS or via a BLE relay.  Unauthenticated
time hints (the BLE `TimeSyncUUID` write, the HTTPS `EnrollResponse.ServerTime`
field) deliberately stay advisory: they update the offset used to construct
the *next* request, but they never write the system clock.

Auto-correction sequence:

```
1. agent sends EnrollRequest  (timestamp = local time, possibly far off)
2. server rejects: "timestamp out of allowed skew"
   └─ response body carries server_time
3. agent computes clock_offset = server_time − local_now
4. agent rebuilds EnrollRequest with timestamp = local_now + clock_offset
5. agent retries once — succeeds if clock_offset was the only problem
```

The retry guard (`clock_adjusted` flag) ensures the agent retries at most
**once** for a clock-skew rejection, preventing an infinite loop if the
server rejects for a different reason.

### BLE relay path

When the device is in BLE-peripheral mode, the relay (smartphone, gateway,
or another Linux device) additionally writes the current time to the
`TimeSyncUUID` GATT characteristic (`6e400005-b5a3-f393-e0a9-e50e24dcca9e`)
**before** starting the enrollment exchange.  The device records this offset
atomically so that the first enrollment request is already clock-corrected —
avoiding the extra round-trip in step 2–4 above.

```
relay                                    device
  │── write TimeSyncUUID: "2026-04-27T14:32:01Z" ──▶ clock_offset stored
  │
  │── read EnrollRequestUUID ──────────────────────▶ build request WITH offset
  │── POST /v1/enroll ─────────────────────────────▶ (server-side)
  │◀─ 200 OK + server_time ─────────────────────────
  │── write EnrollResponseUUID ────────────────────▶ apply bundle
```

If the relay does not write `TimeSyncUUID` first, the single-retry fallback
still applies automatically.

### Configuration

The allowed skew window is controlled by `clock_skew` in the server config
(default `5m`).  Tightening it reduces the replay window; loosening it
accepts requests from devices with worse clocks.  The agents themselves have
no configurable skew limit — they simply trust the server's `server_time`.

## Sensitive payloads (per-module sealing)

Some payloads carry secrets that the ZTP server itself should not retain in
plaintext: a Cumulocity enrollment token is the canonical example, but the
mechanism applies to anything a `PayloadProvider` flags `Sensitive: true`.

The flow is:

```
provider.Build()                                  ← plaintext exists only here
   │  emits Module{Type, Payload, Sensitive: true}
   ▼
engine.sealSensitiveModules(req, mods)
   │  for each Sensitive module:
   │    plaintext = canonicalize(Payload) | RawPayload
   │    Module.Sealed = X25519(plaintext, devicePub) + ChaCha20-Poly1305
   │    Module.Payload = nil; Module.RawPayload = nil
   │    plaintext bytes are zeroed
   ▼
protocol.Sign(bundle)                             ← signs ciphertext only
   ▼
SignedEnvelope → device                           ← bundle bytes contain ciphertext
   ▼
agent.unsealModules()                             ← only the device can decrypt
   ▼
dispatcher.Apply(module)                          ← applier sees plaintext
```

Properties this gives us:

| What sees the plaintext | What sees only ciphertext                 |
|-------------------------|-------------------------------------------|
| issuer HTTP response    | signed bundle bytes (`SignedEnvelope`)    |
| provider stack frame    | server logs, audit log, persisted bundle |
| device RAM (post-unseal)| reverse proxy access logs                |
| device applier process  | BLE relay (when used)                     |

Sealing requires the device to send `EnrollRequest.EphemeralX25519` (the Go
agent always does so). If a sensitive module would be issued to a device that
did not provide an ephemeral key, the engine **rejects** the enrollment
rather than risk leaking the secret in clear text.

The Sealed envelope carries a `format` hint (`json` or `raw`) so the agent
knows whether the decrypted bytes are JSON destined for `Module.Payload` or
opaque bytes destined for `Module.RawPayload` (e.g. the c8y.v2 INI document).
The downstream applier sees the same shape it would have seen in the clear —
sealing is invisible below the dispatcher.

This is independent of (and additive to) **whole-bundle encryption**, which
the agent requests via `EnrollRequest.EncryptBundle = true` for untrusted
transports such as a BLE relay. Per-module sealing happens first; whole-bundle
encryption then wraps the already-sealed signed envelope.

## Cumulocity enrollment tokens (the `c8yissuer` interface)

`tedge cert download c8y` requires a per-device, single-use **enrollment
token** that has been registered against a `newDeviceRequest` in the
Cumulocity tenant. We solve this by separating two responsibilities:

```
                  ┌────────────────────────────────────────┐
                  │ ZTP server                             │
                  │   - holds Ed25519 signing key          │
                  │   - holds admin token                  │
                  │   - DOES NOT hold C8Y credentials      │ ← in remote mode
                  │                                        │
                  │   payload.Cumulocity.Build(device)     │
                  │      │ Mint(externalID, ttl)           │
                  │      ▼                                 │
                  └──────┬─────────────────────────────────┘
                         │ HTTPS (mTLS)
                         ▼
              ┌──────────────────────────────────┐
              │ ztp-c8y-issuer (sidecar)         │
              │   - holds C8Y credentials        │
              │   - egress firewalled to C8Y     │
              │   - separate audit log           │
              └──────────────────────────────────┘
                         │ Cumulocity REST
                         ▼
                Cumulocity tenant: POST /devicecontrol/newDeviceRequests
```

The `c8yissuer.Issuer` interface has just two methods, `Mint` and `Revoke`,
and three implementations:

| Implementation | When to use                                         | Credentials live in              |
|----------------|-----------------------------------------------------|----------------------------------|
| `LocalIssuer`  | small / single-tenant deployments                   | a 0600-mode file on the ZTP host |
| `RemoteIssuer` | production / separation-of-duties / multi-tenant    | only on the sidecar host         |
| `StaticIssuer` | tests, local dev                                    | nowhere (token is fixed)         |

Operational hygiene the implementations enforce:

- `LocalIssuer` refuses to start if its credentials file is not mode 0600.
- `RemoteIssuer` refuses non-`https://` endpoints and requires a client
  cert/key pair (mTLS).
- `StaticIssuer` logs a `WARN` on construction so the fact of its use ends
  up in the operator log.
- No implementation persists the plaintext token. Audit entries record
  `external_id` + `sha256(token)[0:16]` + `expires_at` + outcome.
- The ZTP server engine zeroes the canonical-JSON byte slice after sealing.
  The `Cumulocity` provider drops its local reference to the token before
  returning.

If the bundle delivery later fails, callers can call
`Cumulocity.RevokeForDevice(ctx, device)` to invalidate the unused token in
Cumulocity. Cumulocity also expires the token by TTL even without an
explicit revoke.

### Per-device overrides

The admin API can set `Device.Overrides["c8y_enrollment_token"]` to force a
specific token (use case: the operator pre-registered the device by hand and
wants the bundle to carry exactly that token). The override wins over a
freshly-minted one. Similarly, `c8y_external_id` overrides the
`<prefix>-<device_id>` derivation.
