#!/bin/sh
# c8y.v2 applier — configures a thin-edge.io device for Cumulocity using a
# server-minted, single-use enrollment token.
#
# Stdin (INI):
#   [c8y]
#   url=https://t12345.cumulocity.com
#   tenant=t12345
#   external_id=factory-<machine-id>
#   one_time_password=...
#
# The token is single-use; we do not persist it.
# Pure POSIX shell — no jq, no python.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/lib/ini.sh"

TAB=$(printf '\t')

URL=""; TENANT=""; EXTERNAL_ID=""; TOKEN=""

while IFS="$TAB" read -r SEC IDX KEY VAL; do
    [ "$SEC" = "c8y" ] || continue
    case "$KEY" in
        url)               URL="$VAL" ;;
        tenant)            TENANT="$VAL" ;;
        external_id)       EXTERNAL_ID="$VAL" ;;
        one_time_password) TOKEN="$VAL" ;;
    esac
done <<EOF
$(ini_records)
EOF

[ -n "$URL" ] || { echo "c8y.v2: url is required" >&2; exit 1; }

DEV_ID="$EXTERNAL_ID"
[ -n "$DEV_ID" ] || DEV_ID=$(cat /etc/machine-id 2>/dev/null || hostname)

# normalize the url value
URL=$(echo "$URL" | sed 's|^https://||g'| sed 's|^http://||g')

if command -v tedge >/dev/null 2>&1; then
    tedge config set c8y.url "$URL"
    tedge config set device.id "$DEV_ID"

    if [ -n "$TOKEN" ]; then
        if tedge cert download c8y --help >/dev/null 2>&1; then
            # DEVICE_ONE_TIME_PASSWORD="$TOKEN"
            tedge cert download c8y \
                --device-id "$DEV_ID" \
                --one-time-password "$TOKEN" \
                --url "$URL" \
                || { echo "c8y.v2: tedge cert download c8y failed" >&2; exit 1; }
            unset TOKEN
            # unset C8Y_OTP TOKEN
            sleep 1
            tedge reconnect c8y
        else
            echo "c8y.v2: tedge does not support 'cert download c8y' on this system" >&2
            exit 1
        fi
    fi
    echo "c8y.v2: configured tedge for $URL ($DEV_ID)"
else
    OUT="${ZTP_C8Y_OUT:-/etc/ztp/c8y.env}"
    install -d -m 0755 "$(dirname "$OUT")"
    TMP="$(mktemp)"
    {
        echo "C8Y_URL=$URL"
        echo "C8Y_TENANT=$TENANT"
        echo "C8Y_EXTERNAL_ID=$DEV_ID"
        echo "# one_time_password deliberately not persisted (single-use, short TTL)"
    } > "$TMP"
    install -m 0600 "$TMP" "$OUT"
    rm -f "$TMP"
    echo "c8y.v2: wrote $OUT (tedge not installed; token NOT persisted)"
fi
