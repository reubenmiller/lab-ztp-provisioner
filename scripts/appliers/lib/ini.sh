# shellcheck shell=sh
#
# ini.sh — shared INI parser for ZTP appliers.
#
# Source this from an applier with:
#     . "$(dirname "$0")/lib/ini.sh"
#
# Then on the JSON-free, INI-style payload arriving on stdin call:
#     ini_records | while IFS="$(printf '\t')" read -r SECTION KEY VALUE; do …
#
# Format expected on stdin (also documented in docs/applier-format.md):
#
#   ; comments and # comments are ignored
#   [section]
#   key=value
#
#   [section]                 # repeated sections are list-appended in order
#   key=value
#
#   global_key=value          # keys before the first [section] go to section ""
#
# Rules:
#   - The separator is the FIRST '=' on the line. Values may contain '='.
#   - Trailing whitespace on the line is preserved (we don't try to trim).
#   - Values are single-line; embedded newlines are not supported. Encode
#     binary blobs as a single base64 string instead.
#   - Booleans are the literal strings "true"/"false" (lowercase) or "1"/"0".
#   - Section and key names match [A-Za-z0-9._-]+; everything else is left to
#     individual appliers to validate.
#
# ini_records emits one TAB-separated record per `key=value` line:
#     <section>\t<index>\t<key>\t<value>
# where <index> is the 0-based occurrence count of <section> in the document
# (so repeated [network] blocks get index 0, 1, 2, …). Lines outside any
# section use empty section "" with index 0. Keys with no '=' are silently
# dropped (treated as garbage / continuation lines).

ini_records() {
    awk '
        BEGIN { sec = ""; counts[""] = 0; idx = 0 }
        /^[[:space:]]*$/      { next }
        /^[[:space:]]*[#;]/   { next }
        /^\[.*\][[:space:]]*$/ {
            line = $0
            sub(/^\[/, "", line)
            sub(/\][[:space:]]*$/, "", line)
            sec = line
            if (!(sec in counts)) counts[sec] = -1
            counts[sec]++
            idx = counts[sec]
            next
        }
        {
            i = index($0, "=")
            if (i == 0) next
            key = substr($0, 1, i - 1)
            val = substr($0, i + 1)
            sub(/^[[:space:]]+/, "", key)
            sub(/[[:space:]]+$/, "", key)
            printf "%s\t%d\t%s\t%s\n", sec, idx, key, val
        }
    '
}

# ini_truthy: returns 0 (true) for true/1/yes/on, 1 otherwise.
# Useful for `if ini_truthy "$HID"; then …`
ini_truthy() {
    case "$1" in
        true|TRUE|True|1|yes|YES|on|ON) return 0 ;;
        *) return 1 ;;
    esac
}
