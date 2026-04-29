# Follow-ups

Small, focused work items deferred from a larger PR so the parent
change stayed reviewable. Each entry is meant to be picked up as its
own PR; the description should be enough to re-load context without
re-reading the parent commit.

## ACME TLS mode

Branched off the embed-SPA + TLS-modes work
([c4e514a](../../../commit/c4e514a) / merged into main). The `tls.mode`
enum currently supports `off | cert | selfsigned`; `acme` was
deferred because it requires `golang.org/x/crypto/acme/autocert` and
needs a public DNS name on port 80 (or DNS-01) to actually exercise
end-to-end.

Scope:

- New file [internal/server/tlsmode/acme.go](../internal/server/tlsmode/acme.go) wrapping
  `autocert.Manager`. Cache under `paths.TLSCacheDir()/acme/`
  (re-use the existing dir-creation in `tlsmode.Serve`).
- Add `tls.acme` block to `TLSConfig` in
  [internal/server/config/config.go](../internal/server/config/config.go):
  - `host` (required) — the FQDN being certified.
  - `email` (optional) — Let's Encrypt account contact.
  - `directory_url` (optional) — defaults to LE production; document
    the staging URL in the YAML comment so it's easy to test against.
- Extend `tlsmode.Parse` to accept `acme` and route through `Serve`.
- Document in the yaml example that `acme` mode requires the binary
  to bind port 80 OR be reachable via DNS-01 — fail fast with a
  helpful error if neither is configured.
- README/Architecture update describing when to pick acme vs. Caddy.

Risk to flag: a laptop user behind NAT enabling acme will see
cryptic ACME errors. The error message on validation failure should
mention "expected for laptops without public DNS — use selfsigned
or cert mode instead."

## Path-default wiring in `config.Load`

The [internal/server/paths](../internal/server/paths) package exists
(landed with PR 1, runtime extraction) but its helpers
(`DBPath()`, `SigningKeyPath()`, `AgeKeyPath()`) are not yet
auto-applied. Today an unconfigured `signing_key_file` produces an
ephemeral key (with a warning); the desired UX is to persist under
the OS-native config dir so `./ztp-server` "just runs" portably.

Scope:

- In [internal/server/config/config.go](../internal/server/config/config.go):
  after YAML unmarshal in `Load`, default-fill:
  - `Store.DSN` ← `paths.DBPath()` if `Store.Driver == "sqlite"` and DSN empty.
  - `SigningKeyFile` ← `paths.SigningKeyPath()` if both `SigningKey` and `SigningKeyFile` are empty.
  - `AgeKeyFile` ← `paths.AgeKeyPath()` if both `AgeKey` and `AgeKeyFile` are empty.
- The "no persistent X key configured" warnings in
  [internal/server/runtime/runtime.go](../internal/server/runtime/runtime.go)
  become unreachable for the auto-default path (the file is now
  always set) — replace with an INFO log noting the auto-chosen path
  on first generation.
- Provide an opt-out for tests/CI that genuinely want ephemeral
  state. Simplest: a new top-level `ephemeral: true` field that
  zeros the three path defaults before the runtime sees them. Or:
  honour the existing `store.driver: memory` to also imply ephemeral
  keys.

Behavioural note: this is a real behaviour change for any deployment
that runs without explicit paths today. The docker-compose stack is
unaffected because `deploy/data/...` paths are explicit. Mention in
the changelog and consider a transitional log line for one release.
