#!/bin/sh
# hook.v2 applier — runs a server-supplied script.
#
# Stdin (INI):
#   [hook]
#   interpreter=/bin/sh
#   script_b64=<base64-of-script>
#
# WARNING: NOT enabled by default. Operators must opt in by deploying this
# script into /etc/ztp/appliers.d/. The agent only invokes appliers it
# finds; placing this file is the explicit consent.
#
# Pure POSIX shell — no jq, no python. The script body is base64-encoded so
# multi-line content and arbitrary characters round-trip cleanly.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/lib/ini.sh"

TAB=$(printf '\t')

INTERP="/bin/sh"
SCRIPT_B64=""

while IFS="$TAB" read -r SEC IDX KEY VAL; do
    [ "$SEC" = "hook" ] || continue
    case "$KEY" in
        interpreter) INTERP="$VAL" ;;
        script_b64)  SCRIPT_B64="$VAL" ;;
    esac
done <<EOF
$(ini_records)
EOF

if [ -z "$SCRIPT_B64" ]; then
    echo "hook.v2: empty script, nothing to do"
    exit 0
fi

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT
printf '%s' "$SCRIPT_B64" | base64 -d > "$TMP"
chmod 0700 "$TMP"
echo "hook.v2: running with $INTERP"
"$INTERP" "$TMP"
