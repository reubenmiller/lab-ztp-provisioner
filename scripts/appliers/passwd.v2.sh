#!/bin/sh
# passwd.v2 applier — INI-input variant for setting user passwords.
#
# Stdin format:
#   [user]
#   name=foo
#   password=bar
#
# Multiple [user] sections are supported.
#
# This script must be run as root.
set -eu

SCRIPT_DIR=$(CDPATH="" cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/lib/ini.sh"

TAB=$(printf '\t')

USERNAME=""
PASSWORD=""

ini_records | {
    while IFS="$TAB" read -r SEC IDX KEY VAL; do
        if [ "$SEC" = "user" ]; then
            case "$KEY" in
                name) USERNAME="$VAL" ;;
                password) PASSWORD="$VAL" ;;
            esac
        fi

        # When both USERNAME and PASSWORD are set, apply the change
        if [ -n "$USERNAME" ] && [ -n "$PASSWORD" ]; then
            echo "$USERNAME:$PASSWORD" | chpasswd
            echo "passwd.v2: password updated for $USERNAME"
            USERNAME=""
            PASSWORD=""
        fi
    done
}
