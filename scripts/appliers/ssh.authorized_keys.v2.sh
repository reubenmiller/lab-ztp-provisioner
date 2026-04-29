#!/bin/sh
# ssh.authorized_keys.v2 applier
#
# Stdin (INI):
#   [ssh]
#   user=root
#   key=ssh-ed25519 AAAA... user1@host
#   key=ssh-ed25519 AAAA... user2@host
#
# Multiple `key=` lines are accumulated and written to ~user/.ssh/authorized_keys.
# Pure POSIX shell — no jq, no python.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/lib/ini.sh"

TAB=$(printf '\t')

# Buffer stdin so we can scan the parsed records twice (once for `user=`,
# once to collect keys). Using a single pass with awk would also work but
# this is simpler to maintain.
INPUT_FILE="$(mktemp)"
RECORDS_FILE="$(mktemp)"
KEYS_FILE="$(mktemp)"
trap 'rm -f "$INPUT_FILE" "$RECORDS_FILE" "$KEYS_FILE"' EXIT
cat > "$INPUT_FILE"
ini_records < "$INPUT_FILE" > "$RECORDS_FILE"

USER_NAME=$(awk -F"$TAB" '$1=="ssh" && $3=="user"{u=$4} END{print u}' "$RECORDS_FILE")
[ -n "$USER_NAME" ] || USER_NAME="root"

awk -F"$TAB" '$1=="ssh" && $3=="key" && $4!=""{print $4}' "$RECORDS_FILE" > "$KEYS_FILE"

if [ ! -s "$KEYS_FILE" ]; then
    echo "ssh.authorized_keys.v2: no key= entries, nothing to do"
    exit 0
fi

HOME_DIR=$(getent passwd "$USER_NAME" 2>/dev/null | cut -d: -f6 || true)
if [ -z "$HOME_DIR" ]; then
    echo "ssh.authorized_keys.v2: user $USER_NAME not found" >&2
    exit 1
fi

install -d -m 0700 -o "$USER_NAME" -g "$USER_NAME" "$HOME_DIR/.ssh" 2>/dev/null \
    || install -d -m 0700 "$HOME_DIR/.ssh"
install -m 0600 "$KEYS_FILE" "$HOME_DIR/.ssh/authorized_keys"
chown -R "$USER_NAME:$USER_NAME" "$HOME_DIR/.ssh" 2>/dev/null || true
COUNT=$(wc -l < "$HOME_DIR/.ssh/authorized_keys")
echo "ssh.authorized_keys.v2: installed $COUNT keys for $USER_NAME"
