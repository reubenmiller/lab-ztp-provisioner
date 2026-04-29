#!/bin/sh
# files.v2 applier — drops a list of files onto disk.
#
# Stdin (INI):
#   [file]
#   path=/etc/foo
#   mode=0644
#   owner=root:root
#   contents_b64=<base64-of-contents>
#
# Repeat the [file] section once per file. `contents_b64` is mandatory and
# always base64-encoded (so binary, newlines, and "=" in values just work).
#
# This applier needs only POSIX sh + coreutils (mkdir, install, base64,
# chown). No jq, no python.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/lib/ini.sh"

US=$(printf '\037')
TAB=$(printf '\t')
RECORDS_FILE="$(mktemp)"
trap 'rm -f "$RECORDS_FILE"' EXIT

CUR_SECTION=""
CUR_IDX=""
PATH_=""; MODE="0644"; OWNER=""; B64=""

flush() {
    if [ "$CUR_SECTION" = "file" ] && [ -n "$PATH_" ]; then
        printf '%s%s%s%s%s%s%s\n' \
            "$PATH_" "$US" "$MODE" "$US" "$OWNER" "$US" "$B64" \
            >> "$RECORDS_FILE"
    fi
    PATH_=""; MODE="0644"; OWNER=""; B64=""
}

ini_records | {
    while IFS="$TAB" read -r SEC IDX KEY VAL; do
        if [ "$SEC" != "$CUR_SECTION" ] || [ "$IDX" != "$CUR_IDX" ]; then
            flush
            CUR_SECTION="$SEC"
            CUR_IDX="$IDX"
        fi
        if [ "$SEC" = "file" ]; then
            case "$KEY" in
                path)         PATH_="$VAL" ;;
                mode)         MODE="$VAL" ;;
                owner)        OWNER="$VAL" ;;
                contents_b64) B64="$VAL" ;;
            esac
        fi
    done
    flush
}

if [ ! -s "$RECORDS_FILE" ]; then
    echo "files.v2: no [file] sections in payload, nothing to do"
    exit 0
fi

while IFS="$US" read -r P M O B; do
    DIR=$(dirname "$P")
    install -d -m 0755 "$DIR"
    TMP="$(mktemp)"
    if [ -n "$B" ]; then
        printf '%s' "$B" | base64 -d > "$TMP"
    else
        : > "$TMP"
    fi
    install -m "$M" "$TMP" "$P"
    rm -f "$TMP"
    if [ -n "$O" ]; then
        chown "$O" "$P" 2>/dev/null || true
    fi
    echo "files.v2: wrote $P (mode=$M owner=${O:-default})"
done < "$RECORDS_FILE"
