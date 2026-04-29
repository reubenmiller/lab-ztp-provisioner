#!/bin/sh
# wifi.v2 applier — installs WPA-supplicant or NetworkManager keyfiles
# from an INI-formatted module payload.
#
# Stdin format (no jq required):
#   [network]
#   ssid=FactoryNet
#   password=factory-pass
#   key_mgmt=WPA-PSK
#   hidden=false
#   priority=0
#
#   [network]
#   ssid=Guest
#   key_mgmt=NONE
#   hidden=true
#   priority=2
#
# Backend selection:
#   ZTP_WIFI_BACKEND=wpa_supplicant | networkmanager | auto   (default: auto)
# Output paths:
#   ZTP_WIFI_WPA_OUT  default /etc/wpa_supplicant/wpa_supplicant.conf
#   ZTP_WIFI_NM_DIR   default /etc/NetworkManager/system-connections
set -eu

# Locate the shared lib relative to this script. The applier dir layout is:
#   scripts/appliers/wifi.v2.sh
#   scripts/appliers/lib/ini.sh
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/lib/ini.sh"

# ---- collect networks ----------------------------------------------------
# We accumulate fields per [network] section and flush whenever the section
# or its index changes (so repeated [network] blocks each become one record).
# Records are written using ASCII Unit Separator (0x1F) instead of TAB so
# that empty fields are preserved across `read` (POSIX read collapses runs
# of whitespace-class IFS characters).
RECORDS_FILE="$(mktemp)"
trap 'rm -f "$RECORDS_FILE"' EXIT
US=$(printf '\037')
TAB=$(printf '\t')

CUR_SECTION=""
CUR_IDX=""
SSID=""; PSK=""; KM=""; HID="false"; PRI="0"

flush() {
    if [ "$CUR_SECTION" = "network" ] && [ -n "$SSID" ]; then
        printf '%s%s%s%s%s%s%s%s%s\n' \
            "$SSID" "$US" "$PSK" "$US" "$KM" "$US" "$HID" "$US" "$PRI" \
            >> "$RECORDS_FILE"
    fi
    SSID=""; PSK=""; KM=""; HID="false"; PRI="0"
}

ini_records | {
    while IFS="$TAB" read -r SEC IDX KEY VAL; do
        if [ "$SEC" != "$CUR_SECTION" ] || [ "$IDX" != "$CUR_IDX" ]; then
            flush
            CUR_SECTION="$SEC"
            CUR_IDX="$IDX"
        fi
        if [ "$SEC" = "network" ]; then
            case "$KEY" in
                ssid)     SSID="$VAL" ;;
                password) PSK="$VAL" ;;
                key_mgmt) KM="$VAL" ;;
                hidden)   HID="$VAL" ;;
                priority) PRI="$VAL" ;;
            esac
        fi
    done
    flush
}

if [ ! -s "$RECORDS_FILE" ]; then
    echo "wifi.v2: no [network] sections in payload, nothing to do"
    exit 0
fi

# ---- pick a backend ------------------------------------------------------
BACKEND="${ZTP_WIFI_BACKEND:-auto}"
if [ "$BACKEND" = "auto" ]; then
    if command -v nmcli >/dev/null 2>&1 || [ -d /etc/NetworkManager ]; then
        BACKEND=networkmanager
    else
        BACKEND=wpa_supplicant
    fi
fi

wpa_keymgmt() {
    KM_IN="$1"; PSK_IN="$2"
    if [ "$KM_IN" = "NONE" ] || [ -z "$PSK_IN" ]; then
        echo "NONE"
    elif [ -n "$KM_IN" ]; then
        echo "$KM_IN"
    else
        echo "WPA-PSK"
    fi
}

case "$BACKEND" in
    wpa_supplicant)
        OUT="${ZTP_WIFI_WPA_OUT:-/etc/wpa_supplicant/wpa_supplicant.conf}"
        TMP="$(mktemp)"
        {
            echo "ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev"
            echo "update_config=1"
            echo
            while IFS="$US" read -r SSID PSK KM HID PRI; do
                MODE=$(wpa_keymgmt "$KM" "$PSK")
                echo "network={"
                printf '    ssid="%s"\n' "$SSID"
                if [ "$MODE" = "NONE" ]; then
                    echo "    key_mgmt=NONE"
                else
                    echo "    key_mgmt=$MODE"
                    printf '    psk="%s"\n' "$PSK"
                fi
                if ini_truthy "$HID"; then echo "    scan_ssid=1"; fi
                [ "$PRI" -gt 0 ] 2>/dev/null && echo "    priority=$PRI"
                echo "}"
            done < "$RECORDS_FILE"
        } > "$TMP"
        install -d -m 0755 "$(dirname "$OUT")"
        install -m 0600 "$TMP" "$OUT"
        rm -f "$TMP"
        echo "wifi.v2: wrote $OUT (wpa_supplicant)"
        ;;

    networkmanager)
        NM_DIR="${ZTP_WIFI_NM_DIR:-/etc/NetworkManager/system-connections}"
        install -d -m 0700 "$NM_DIR"
        while IFS="$US" read -r SSID PSK KM HID PRI; do
            SAFE=$(printf '%s' "$SSID" | tr -c 'A-Za-z0-9._-' '_')
            FILE="$NM_DIR/ztp-$SAFE.nmconnection"
            TMP="$(mktemp)"
            if [ "$KM" = "NONE" ] || [ -z "$PSK" ]; then
                NM_KEY_MGMT=""
            else
                NM_KEY_MGMT="wpa-psk"
            fi
            {
                echo "[connection]"
                echo "id=ztp-$SSID"
                echo "type=wifi"
                echo "autoconnect=true"
                echo
                echo "[wifi]"
                echo "mode=infrastructure"
                echo "ssid=$SSID"
                if ini_truthy "$HID"; then echo "hidden=true"; fi
                echo
                if [ -n "$NM_KEY_MGMT" ]; then
                    echo "[wifi-security]"
                    echo "key-mgmt=$NM_KEY_MGMT"
                    echo "psk=$PSK"
                    echo
                fi
                echo "[ipv4]"
                echo "method=auto"
                echo
                echo "[ipv6]"
                echo "method=auto"
            } > "$TMP"
            install -m 0600 "$TMP" "$FILE"
            rm -f "$TMP"
            echo "wifi.v2: wrote $FILE (NetworkManager)"
        done < "$RECORDS_FILE"
        if command -v nmcli >/dev/null 2>&1; then
            nmcli connection reload >/dev/null 2>&1 || true
        fi
        ;;

    *)
        echo "wifi.v2: unknown ZTP_WIFI_BACKEND='$BACKEND' (want wpa_supplicant|networkmanager|auto)" >&2
        exit 2
        ;;
esac
