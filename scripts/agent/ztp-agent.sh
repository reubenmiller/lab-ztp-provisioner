#!/bin/sh
# ztp-agent.sh — POSIX shell agent for Zero-Touch Provisioning.
#
# Small-footprint alternative to the Go agent. Speaks the same wire protocol
# but uses the server's `Accept: text/plain` rendering, so it never needs a
# JSON parser. Suitable for minimal embedded images.
#
# Required tools:
#   curl, openssl (with Ed25519 + X25519 — OpenSSL 1.1.1+ / LibreSSL 3.7+),
#   base64, awk, sed, head, tr, xxd, mktemp
#
# Environment / flags:
#   ZTP_SERVER          server URL, e.g. https://ztp.example.com
#                       If unset, ZTP_SERVER_LIST is tried in order.
#   ZTP_SERVER_LIST     comma-separated fallback URLs tried when ZTP_SERVER is
#                       not set or not reachable, e.g. https://localhost:8443
#   ZTP_SERVER_PUBKEY   base64 Ed25519 server signing public key (auto-fetched)
#   ZTP_DEVICE_ID       optional; default = /etc/machine-id, else hostname
#   ZTP_TOKEN           optional bootstrap token
#   ZTP_PROFILE         optional advisory profile-name hint sent to the server.
#                       Server treats it as a hint only; any operator-side
#                       binding (allowlist/token, sticky persisted name,
#                       device override, fact-based selector) wins over it.
#   ZTP_IDENTITY_KEY    PEM Ed25519 private key path (auto-generated)
#   ZTP_APPLIERS_DIR    default /etc/ztp/appliers.d
#   ZTP_CA              optional PEM CA cert pin
#   ZTP_INSECURE        skip TLS verification (curl -k); dev/testing only — never use in production
#   ZTP_DEBUG           dump the verified manifest to stderr:
#                         1 / true / yes / on  → dump, then run appliers
#                         only / dump / inspect → dump, then exit 0 (no appliers)
#
# Sealed (per-module) payloads:
#   The server seals modules carrying secrets (e.g. Cumulocity enrollment
#   tokens) end-to-end with X25519 + ChaCha20-Poly1305. The agent generates a
#   fresh ephemeral X25519 keypair per run, advertises the public half in the
#   EnrollRequest, and decrypts module-sealed=… manifest lines locally.
#
#   Note: openssl(1) deliberately refuses AEAD modes in `enc`, so the agent
#   uses raw `openssl enc -chacha20` (counter=1) and discards the trailing
#   16-byte Poly1305 tag. This is sound because the entire text manifest —
#   including each ciphertext_b64 — is already authenticated by the server's
#   Ed25519 signature, which the agent verifies before doing anything else.
#
# Edge cases not implemented in this script (use the Go agent instead):
#   - chunked BLE transport
#   - mDNS discovery
#   - whole-bundle EncryptedPayload (only per-module sealing is supported)
set -eu

# ---------------------------------------------------------------------------
# Argument parsing — command-line flags override env-variable config.
# Supported flags:
#
#   --debug              Set ZTP_DEBUG=1 (dump manifest, then run appliers)
#   --debug <mode>       Set ZTP_DEBUG=<mode> (mode: 1/true/yes/on/only/dump/inspect)
#   --debug=<mode>       Same as above, using = form
#   --insecure           Skip TLS certificate verification (sets ZTP_INSECURE=1)
#   --profile <name>     Advisory profile-name hint (sets ZTP_PROFILE)
#   --profile=<name>     Same as above, using = form
# ---------------------------------------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        --debug=*) ZTP_DEBUG="${1#--debug=}"; shift ;;
        --debug)
            shift
            # If the next token looks like a mode value (no leading dash, non-empty),
            # consume it; otherwise default to "1" (dump + run appliers).
            case "${1:-}" in
                ''|-*) ZTP_DEBUG="${ZTP_DEBUG:-1}" ;;
                *)     ZTP_DEBUG="$1"; shift ;;
            esac ;;
        --insecure) ZTP_INSECURE=1; shift ;;
        --profile=*) ZTP_PROFILE="${1#--profile=}"; shift ;;
        --profile) shift; ZTP_PROFILE="${1:-}"; [ $# -gt 0 ] && shift ;;
        --) shift; break ;;
        -*) printf 'warning: unknown flag: %s\n' "$1" >&2; shift ;;
        *)  break ;;
    esac
done

: "${ZTP_SERVER:=}"
: "${ZTP_SERVER_PUBKEY:=}"
: "${ZTP_IDENTITY_KEY:=/var/lib/ztp/identity.pem}"
: "${ZTP_APPLIERS_DIR:=/etc/ztp/appliers.d}"
: "${ZTP_INSECURE:=}"
DEVICE_ID="${ZTP_DEVICE_ID:-$(cat /etc/machine-id 2>/dev/null || hostname)}"

# Build CURL_OPTS once: --cacert when ZTP_CA is set, -k when ZTP_INSECURE is set.
CURL_OPTS=""
[ -n "${ZTP_CA:-}" ] && CURL_OPTS="--cacert $ZTP_CA"
[ -n "${ZTP_INSECURE:-}" ] && CURL_OPTS="$CURL_OPTS -k"

log() { printf '%s\n' "$*" >&2; }

# If ZTP_SERVER is not set, walk ZTP_SERVER_LIST (comma-separated) and use
# the first URL that responds to a TCP connect on its port (3 s timeout).
if [ -z "${ZTP_SERVER}" ] && [ -n "${ZTP_SERVER_LIST:-}" ]; then
    _IFS_SAVE="$IFS"
    IFS=','
    for _candidate in ${ZTP_SERVER_LIST}; do
        IFS="$_IFS_SAVE"
        _candidate=$(printf '%s' "$_candidate" | tr -d ' ')
        [ -z "$_candidate" ] && continue
        # Extract host:port from URL for TCP probe.
        _host=$(printf '%s' "$_candidate" | sed 's|^https\?://||;s|/.*||;s|:.*||')
        _port=$(printf '%s' "$_candidate" | sed 's|^https\?://[^:/]*||;s|/.*||;s|^:||')
        case "$_candidate" in https://*) _defport=443 ;; *) _defport=80 ;; esac
        [ -z "$_port" ] && _port="$_defport"
        if (echo "" | timeout 3 nc -w 3 "$_host" "$_port") 2>/dev/null; then
            ZTP_SERVER="$_candidate"
            log "server-list: using $ZTP_SERVER"
            break
        fi
        log "server-list: $ZTP_SERVER_LIST not reachable, skipping"
    done
    IFS="$_IFS_SAVE"
fi

if [ -z "${ZTP_SERVER}" ]; then
    printf 'ZTP_SERVER is required (or set ZTP_SERVER_LIST with fallback URLs)\n' >&2
    exit 1
fi

# Extract the value of a key from a "key=value" stream on stdin. Last
# occurrence wins (matches typical text/plain semantics). Empty if absent.
kv_get() { awk -F= -v k="$1" 'BEGIN{v=""} $1==k{ sub(/^[^=]*=/,"",$0); v=$0 } END{print v}'; }

# JSON-string-escape STR (no surrounding quotes). Used only for outgoing
# request fields; incoming responses are text/plain.
json_escape() {
    printf '%s' "$1" | awk '
    BEGIN {
        for (i = 0; i < 32; i++) ctrl[sprintf("%c", i)] = sprintf("\\u%04x", i)
        ctrl["\""] = "\\\""; ctrl["\\"] = "\\\\"
        ctrl["\b"] = "\\b"; ctrl["\f"] = "\\f"; ctrl["\n"] = "\\n"
        ctrl["\r"] = "\\r"; ctrl["\t"] = "\\t"
    }
    { for (i = 1; i <= length($0); i++) {
        c = substr($0, i, 1); printf "%s", (c in ctrl) ? ctrl[c] : c } }'
}

# ---------------------------------------------------------------------------
# Identity key
# ---------------------------------------------------------------------------
mkdir -p "$(dirname "$ZTP_IDENTITY_KEY")"
chmod 700 "$(dirname "$ZTP_IDENTITY_KEY")" 2>/dev/null || true
if [ ! -f "$ZTP_IDENTITY_KEY" ]; then
    log "generating new ed25519 identity key at $ZTP_IDENTITY_KEY"
    openssl genpkey -algorithm ed25519 -out "$ZTP_IDENTITY_KEY"
    chmod 600 "$ZTP_IDENTITY_KEY"
fi
PUB_B64=$(openssl pkey -in "$ZTP_IDENTITY_KEY" -pubout -outform DER 2>/dev/null \
    | tail -c 32 | base64 | tr -d '\n')

# ---------------------------------------------------------------------------
# Ephemeral X25519 keypair (one per agent run). The public half is advertised
# in the EnrollRequest; the server uses it to seal per-module secrets so the
# plaintext never lands in the bundle, audit log, BLE relay, or reverse proxy.
# The private key lives only in $TMPDIR for this process and is removed by the
# EXIT trap installed below.
# ---------------------------------------------------------------------------
EPHEM_KEY=$(mktemp)
openssl genpkey -algorithm x25519 -out "$EPHEM_KEY" 2>/dev/null
EPHEM_PUB_B64=$(openssl pkey -in "$EPHEM_KEY" -pubout -outform DER 2>/dev/null \
    | tail -c 32 | base64 | tr -d '\n')

# ---------------------------------------------------------------------------
# Build canonical EnrollRequest (RFC 8785-ish: keys lexicographically sorted,
# no whitespace). We construct it manually so the shell side never needs JSON
# parsing OR jq, even for outgoing payloads.
#
# The nonce + timestamp must be FRESH on every attempt — the server rejects
# replays — so this is a function called once per retry, not a one-shot.
# ---------------------------------------------------------------------------
HOSTNAME_VAL=$(hostname 2>/dev/null || echo "")
MACHINE_ID=$(cat /etc/machine-id 2>/dev/null || echo "")
ARCH=$(uname -m 2>/dev/null || echo "")

build_envelope() {
    NONCE=$(head -c 16 /dev/urandom | base64 | tr -d '\n')
    TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    facts="{\"arch\":\"$(json_escape "$ARCH")\""
    facts="$facts,\"hostname\":\"$(json_escape "$HOSTNAME_VAL")\""
    facts="$facts,\"machine_id\":\"$(json_escape "$MACHINE_ID")\""
    facts="$facts,\"os\":\"linux\"}"

    # Lexicographic key order: bootstrap_token < device_id < ephemeral_x25519
    # < facts < metadata < nonce < protocol_version < public_key < timestamp.
    CANON="{"
    [ -n "${ZTP_TOKEN:-}" ] && CANON="$CANON\"bootstrap_token\":\"$(json_escape "$ZTP_TOKEN")\","
    CANON="$CANON\"device_id\":\"$(json_escape "$DEVICE_ID")\""
    CANON="$CANON,\"ephemeral_x25519\":\"$EPHEM_PUB_B64\""
    CANON="$CANON,\"facts\":$facts"
    # Optional advisory profile hint. Wire-compatible with Go/Rust agents,
    # which send metadata as map[string]string. We only emit the field when
    # ZTP_PROFILE is non-empty so the canonical form stays minimal otherwise.
    [ -n "${ZTP_PROFILE:-}" ] && CANON="$CANON,\"metadata\":{\"profile\":\"$(json_escape "$ZTP_PROFILE")\"}"
    CANON="$CANON,\"nonce\":\"$NONCE\""
    CANON="$CANON,\"protocol_version\":\"1\""
    CANON="$CANON,\"public_key\":\"$PUB_B64\""
    CANON="$CANON,\"timestamp\":\"$TS\"}"

    # openssl pkeyutl -rawin needs a seekable file, not a pipe.
    TMP_CANON=$(mktemp)
    printf '%s' "$CANON" > "$TMP_CANON"
    SIG_B64=$(openssl pkeyutl -sign -inkey "$ZTP_IDENTITY_KEY" -rawin -in "$TMP_CANON" \
        | base64 | tr -d '\n')
    rm -f "$TMP_CANON"
    PAYLOAD_B64=$(printf '%s' "$CANON" | base64 | tr -d '\n')

    ENVELOPE="{\"protocol_version\":\"1\",\"key_id\":\"device\",\"alg\":\"ed25519\",\"payload\":\"$PAYLOAD_B64\",\"signature\":\"$SIG_B64\"}"
}

# ---------------------------------------------------------------------------
# If no pubkey was supplied, fetch it from the server's unauthenticated
# /v1/server-info endpoint. Accept: text/plain returns key=value lines so
# kv_get can extract the value without any JSON parser.
# ---------------------------------------------------------------------------
if [ -z "$ZTP_SERVER_PUBKEY" ]; then
    log "ZTP_SERVER_PUBKEY not set; fetching from $ZTP_SERVER/v1/server-info"
    [ -z "${ZTP_CA:-}" ] && [ -z "${ZTP_INSECURE:-}" ] && log "WARNING: fetching server pubkey without a CA cert — TOFU trust (set ZTP_CA to pin the certificate)"
    ZTP_SERVER_PUBKEY=$(curl -sS $CURL_OPTS \
        -H 'Accept: text/plain' \
        "$ZTP_SERVER/v1/server-info" \
        | kv_get public_key)
    [ -z "$ZTP_SERVER_PUBKEY" ] && { log "failed to fetch server pubkey from /v1/server-info"; exit 1; }
    log "fetched server pubkey from /v1/server-info"
fi

# ---------------------------------------------------------------------------
# Materialise the server pubkey as a PEM file once (shared by all openssl
# verify calls below).
# ---------------------------------------------------------------------------
SERVER_PUB_PEM=$(mktemp)
trap 'rm -f "$SERVER_PUB_PEM" "$EPHEM_KEY"' EXIT
{
    # DER prefix for Ed25519 SubjectPublicKeyInfo (12 bytes) + raw 32-byte key.
    printf '\060\052\060\005\006\003\053\145\160\003\041\000'
    printf '%s' "$ZTP_SERVER_PUBKEY" | base64 -d
} | openssl pkey -pubin -inform DER -out "$SERVER_PUB_PEM" 2>/dev/null

# ---------------------------------------------------------------------------
# Enrollment loop. Server responds with "key=value" lines when we ask for it.
# ---------------------------------------------------------------------------
verify_sig() {
    # verify_sig <body-file> <b64-signature>
    sig=$(mktemp)
    printf '%s' "$2" | base64 -d > "$sig"
    rc=0
    openssl pkeyutl -verify -pubin -inkey "$SERVER_PUB_PEM" -rawin \
        -in "$1" -sigfile "$sig" >/dev/null 2>&1 || rc=$?
    rm -f "$sig"
    return $rc
}

# decrypt_sealed <ephem_pub_b64> <nonce_b64> <ct_b64>
# Decrypts a sealed module payload using the agent's ephemeral X25519 private
# key + the server's per-module ephemeral X25519 public key. The shared secret
# is used as a raw ChaCha20 key (counter=1, little-endian, prepended to the
# 12-byte nonce). The trailing 16-byte Poly1305 tag is dropped: openssl enc
# refuses AEAD modes, but the outer Ed25519 manifest signature already
# authenticates these ciphertext bytes, so the tag is redundant here.
# Plaintext is written to stdout.
decrypt_sealed() {
    _peer_pub=$(mktemp)
    {
        # X25519 SubjectPublicKeyInfo DER prefix (12 bytes) + raw 32-byte key.
        printf '\060\052\060\005\006\003\053\145\156\003\041\000'
        printf '%s' "$1" | base64 -d
    } | openssl pkey -pubin -inform DER -out "$_peer_pub" 2>/dev/null
    _shared=$(openssl pkeyutl -derive -inkey "$EPHEM_KEY" -peerkey "$_peer_pub" 2>/dev/null \
        | xxd -p | tr -d '\n')
    _nonce_hex=$(printf '%s' "$2" | base64 -d | xxd -p | tr -d '\n')
    _ct=$(mktemp)
    printf '%s' "$3" | base64 -d > "$_ct"
    _pt_size=$(( $(wc -c < "$_ct" | tr -d ' ') - 16 ))
    head -c "$_pt_size" < "$_ct" \
        | openssl enc -chacha20 -K "$_shared" -iv "01000000${_nonce_hex}" -d
    rm -f "$_ct" "$_peer_pub"
}

RESP_FILE=$(mktemp)
trap 'rm -f "$SERVER_PUB_PEM" "$EPHEM_KEY" "$RESP_FILE"' EXIT

while :; do
    build_envelope
    printf '%s' "$ENVELOPE" \
        | curl -sS $CURL_OPTS -X POST \
            -H 'Content-Type: application/json' \
            -H 'Accept: text/plain' \
            --data-binary @- "$ZTP_SERVER/v1/enroll" \
        > "$RESP_FILE"

    STATUS=$(kv_get status < "$RESP_FILE")
    case "$STATUS" in
        accepted) break ;;
        rejected)
            REASON=$(kv_get reason < "$RESP_FILE")
            log "rejected: $REASON"; exit 1 ;;
        pending)
            DELAY=$(kv_get retry_after < "$RESP_FILE")
            [ -z "$DELAY" ] && DELAY=10
            REASON=$(kv_get reason < "$RESP_FILE")
            log "pending; reason=\"$REASON\"; retry in ${DELAY}s"
            sleep "$DELAY"
            continue ;;
        *)
            log "unexpected status: '$STATUS'"
            log "raw response:"
            sed 's/^/  /' < "$RESP_FILE" >&2
            exit 1 ;;
    esac
done

# ---------------------------------------------------------------------------
# Verify the text manifest signature, then iterate modules with awk.
# ---------------------------------------------------------------------------
MAN_PAYLOAD_B64=$(kv_get manifest.payload < "$RESP_FILE")
MAN_SIG_B64=$(kv_get manifest.signature < "$RESP_FILE")

if [ -z "$MAN_PAYLOAD_B64" ] || [ -z "$MAN_SIG_B64" ]; then
    log "server did not return a text manifest"
    exit 1
fi

MANIFEST=$(mktemp)
trap 'rm -f "$SERVER_PUB_PEM" "$EPHEM_KEY" "$RESP_FILE" "$MANIFEST"' EXIT
printf '%s' "$MAN_PAYLOAD_B64" | base64 -d > "$MANIFEST"

if ! verify_sig "$MANIFEST" "$MAN_SIG_B64"; then
    log "manifest signature verification FAILED"
    exit 1
fi
log "manifest signature OK"

# ---------------------------------------------------------------------------
# Apply modules. The manifest has one "module=<type> <b64-payload>" line per
# module — trivially parseable with awk; the applier receives the decoded
# payload bytes on stdin.
#
# Set ZTP_DEBUG=1 to dump the manifest (one line per module + decoded payload)
# to stderr before invoking appliers. ZTP_DEBUG=only goes a step further and
# *only* dumps, skipping the applier dispatch entirely — useful when you want
# to inspect what the server is delivering without installing any appliers.
# ---------------------------------------------------------------------------
debug_dump() {
    log "=== manifest ($(wc -l < "$MANIFEST" | tr -d ' ') lines) ==="
    sed 's/^/  | /' < "$MANIFEST" >&2
    log "=== decoded module payloads ==="
    awk -F= '$1 == "module" { sub(/^module=/, ""); print }' "$MANIFEST" \
    | while IFS=' ' read -r TYPE PAYLOAD_B64; do
        [ -z "$TYPE" ] && continue
        log "--- module: $TYPE ---"
        printf '%s' "$PAYLOAD_B64" | base64 -d | sed 's/^/  | /' >&2 || true
        printf '\n' >&2
    done
    awk -F= '$1 == "module-sealed" { sub(/^module-sealed=/, ""); print }' "$MANIFEST" \
    | while IFS=' ' read -r TYPE FORMAT EPHEM_B64 NONCE_B64 CT_B64; do
        [ -z "$TYPE" ] && continue
        log "--- module (sealed): $TYPE [format=$FORMAT] ---"
        decrypt_sealed "$EPHEM_B64" "$NONCE_B64" "$CT_B64" \
            | sed 's/^/  | /' >&2 || true
        printf '\n' >&2
    done
    log "=== end manifest ==="
}

case "${ZTP_DEBUG:-}" in
    only|dump|inspect)
        debug_dump
        log "ZTP_DEBUG=$ZTP_DEBUG: skipping applier dispatch"
        exit 0 ;;
    1|true|yes|on)
        debug_dump ;;
esac

log "applying bundle (appliers dir: $ZTP_APPLIERS_DIR)"
RC=0
APPLIED=0
SKIPPED=0
# Plain (unsealed) modules: "module=<type> <b64-payload>"
awk -F= '$1 == "module" { sub(/^module=/, ""); print }' "$MANIFEST" \
| while IFS=' ' read -r TYPE PAYLOAD_B64; do
    [ -z "$TYPE" ] && continue
    SCRIPT="$ZTP_APPLIERS_DIR/$TYPE.sh"
    if [ -x "$SCRIPT" ]; then
        log "  -> $TYPE  (applier: $SCRIPT)"
        printf '%s' "$PAYLOAD_B64" | base64 -d | "$SCRIPT" || RC=$?
        APPLIED=$((APPLIED + 1))
    else
        log "  -> $TYPE  (skipped: no applier at $SCRIPT — set ZTP_DEBUG=1 to inspect payload)"
        SKIPPED=$((SKIPPED + 1))
    fi
done

# Sealed modules: "module-sealed=<type> <format> <ephem_pub_b64> <nonce_b64> <ct_b64>"
awk -F= '$1 == "module-sealed" { sub(/^module-sealed=/, ""); print }' "$MANIFEST" \
| while IFS=' ' read -r TYPE FORMAT EPHEM_B64 NONCE_B64 CT_B64; do
    [ -z "$TYPE" ] && continue
    SCRIPT="$ZTP_APPLIERS_DIR/$TYPE.sh"
    if [ -x "$SCRIPT" ]; then
        log "  -> $TYPE  (applier: $SCRIPT, sealed format=$FORMAT)"
        decrypt_sealed "$EPHEM_B64" "$NONCE_B64" "$CT_B64" | "$SCRIPT" || RC=$?
        APPLIED=$((APPLIED + 1))
    else
        log "  -> $TYPE  (skipped: no applier at $SCRIPT — sealed payload not decrypted)"
        SKIPPED=$((SKIPPED + 1))
    fi
done

if [ "$RC" -ne 0 ]; then
    log "one or more appliers failed (rc=$RC)"
    exit "$RC"
fi
log "provisioning complete"
