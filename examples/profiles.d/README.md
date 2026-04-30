# Provisioning profiles

One YAML file per profile. The server loads every `*.yaml` / `*.yml` in
this directory at startup and on `kill -HUP <pid>` (or `POST
/v1/admin/profiles/reload`).

Each device is matched to exactly one profile via the resolver's precedence
chain:

1. `Device.Overrides["_profile"]` (operator-set override)
2. `Device.ProfileName` (sticky from prior enrollment)
3. Verifier hint (allowlist entry / bootstrap token)
4. Selector match (priority-desc, name-asc)
5. `default_profile` from `ztp-server.yaml`
6. Literal profile named `default`

When nothing matches, enrollment is **rejected**.

## Secret handling

- `${VAR}` and `${VAR:-default}` interpolation is run on every string leaf.
- For multi-secret rotation, encrypt the whole file with SOPS-age. The
  server has a built-in age decoder (no `sops` CLI required at runtime),
  and `ztpctl` ships matching seal/edit commands so you don't need
  upstream sops on operator workstations either:

  ```sh
  # First time: server publishes its public key on first start; ztpctl
  # fetches it from the admin API and seals every leaf matching the regex.
  ztpctl secrets seal default.yaml --regex '^(password|bootstrap_token|static_token|.*secret.*)$'

  # Subsequent edits open the file in $EDITOR with plaintext; saving
  # re-encrypts using the same rules and recipients automatically.
  ztpctl secrets edit default.yaml

  # Print plaintext to stdout (gated to avoid accidental disclosure).
  ztpctl secrets reveal default.yaml --yes-show-secrets
  ```

  Files are byte-compatible with the upstream `sops` CLI, so operators who
  already have a SOPS workflow (`sops -e -i default.yaml`,
  `sops default.yaml`) can use it interchangeably. Configure
  `age_key_file` and optional extra `age_recipients` in `ztp-server.yaml`
  to plug into an existing key-management story.

- `GET /v1/admin/profiles/{name}` redacts every `ztp:"sensitive"` field
  (wifi password, c8y `static_token`, hook script, file contents) so admin
  UI screenshots and audit trails are safe to share.

## Validation

Profile names must match `^[a-z0-9][a-z0-9_-]{0,62}$`. The file stem is
used as the name when the YAML omits the `name:` field.
