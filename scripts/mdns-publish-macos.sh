#!/bin/sh
# mdns-publish-macos.sh — advertise the local ZTP server on the Mac LAN via
# Bonjour. Required on macOS+colima because Docker host networking only
# reaches the colima VM, not the Mac LAN. dns-sd ships with macOS.
#
# Reads deploy/.env automatically when called via `just mdns-publish-macos`
# (justfile sets dotenv-load). Env vars in order of precedence:
#
#   ZTP_SERVER  — full URL override, e.g. https://192.168.1.10:8443
#   ZTP_HTTPS_PORT + ZTP_CADDYFILE — used to derive scheme/port from .env
#   PORT        — raw port override (lowest priority)
#
# Usage:
#   just mdns-publish-macos                          # reads deploy/.env
#   ZTP_SERVER=https://localhost:8443 ./scripts/mdns-publish-macos.sh
#   HOST=ztp.custom.local. ./scripts/mdns-publish-macos.sh   # override SRV host
#
# Press Ctrl-C to stop advertising. Re-run after restarting the server.

set -eu

# Derive defaults from deploy/.env values when ZTP_SERVER is not set explicitly.
# ZTP_HTTPS_PORT is set by `just init` (e.g. 8443). The variable name itself
# tells us the scheme — if ZTP_HTTPS_PORT is set, it's HTTPS. Fall back to
# ZTP_CADDYFILE pattern-matching or plain http for manual PORT overrides.
# Use ZTP_SITE_ADDRESS (e.g. ztp.local) as the host for fetching server-info
# so that Caddy's virtual host routing resolves correctly.
if [ -z "${ZTP_SERVER:-}" ]; then
  _host="${ZTP_SITE_ADDRESS:-localhost}"
  if [ -n "${ZTP_HTTPS_PORT:-}" ]; then
    # ZTP_HTTPS_PORT explicitly names the HTTPS port.
    ZTP_SERVER="https://${_host}:${ZTP_HTTPS_PORT}"
  else
    _port="${PORT:-8080}"
    case "${ZTP_CADDYFILE:-}" in
      *mkcert*|*tls*) _scheme="https" ;;
      *) _scheme="http" ;;
    esac
    ZTP_SERVER="${_scheme}://${_host}:${_port}"
  fi
fi
PORT="${PORT:-${ZTP_HTTPS_PORT:-8080}}"
INSTANCE="${INSTANCE:-ZTP Server ($(scutil --get ComputerName 2>/dev/null || hostname -s))}"
SERVICE="${SERVICE:-_ztp._tcp}"

if ! command -v dns-sd >/dev/null 2>&1; then
  echo "dns-sd not found — this script is macOS only" >&2
  exit 1
fi

# Pick a LAN IPv4 using routing hints instead of hardcoded interface order.
# 1) Interface for route to ZTP_SERVER host.
# 2) Interface for default route.
# 3) First non-loopback IPv4 on any interface.
LAN_IP=""
_server_host=$(printf '%s' "$ZTP_SERVER" | sed -E 's#^[a-zA-Z]+://([^/:]+).*#\1#')
_route_iface=""
if [ -n "$_server_host" ]; then
  _route_iface=$(route -n get "$_server_host" 2>/dev/null | awk '/interface:/{print $2; exit}')
fi
if [ -z "$_route_iface" ]; then
  _route_iface=$(route -n get default 2>/dev/null | awk '/interface:/{print $2; exit}')
fi
if [ -n "$_route_iface" ]; then
  LAN_IP=$(ipconfig getifaddr "$_route_iface" 2>/dev/null || true)
fi
if [ -z "$LAN_IP" ]; then
  for iface in $(ifconfig -l); do
    ip=$(ipconfig getifaddr "$iface" 2>/dev/null || true)
    case "$ip" in
      ""|127.*) continue ;;
      *) LAN_IP="$ip"; break ;;
    esac
  done
fi
if [ -z "$LAN_IP" ]; then
  echo "could not detect a LAN IPv4 address" >&2
  exit 1
fi

# Pull the pubkey + version straight from the running server so the TXT
# records match what the in-process advertiser would have published.
INFO=$(curl -fsS --max-time 3 "$ZTP_SERVER/v1/server-info" 2>/dev/null || true)
case "$ZTP_SERVER" in https://*) _scheme="https" ;; *) _scheme="http" ;; esac
if [ -z "$INFO" ]; then
  echo "warn: $ZTP_SERVER/v1/server-info unreachable; advertising without pubkey TXT" >&2
  TXT="scheme=$_scheme"
else
  PUBKEY=$(printf '%s' "$INFO" | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')
  VERSION=$(printf '%s' "$INFO" | sed -n 's/.*"protocol_version":"\([^"]*\)".*/\1/p')
  TXT="scheme=$_scheme"
  [ -n "$VERSION" ] && TXT="$TXT version=$VERSION"
  [ -n "$PUBKEY" ]  && TXT="$TXT pubkey=$PUBKEY"
fi

HOST="${HOST:-ztp.local.}"
echo "advertising $SERVICE on $LAN_IP:$PORT (host=$HOST instance=\"$INSTANCE\")"
echo "TXT: ${TXT:-<none>}"
echo "Ctrl-C to stop."

# dns-sd -P arguments:
#   <Name> <Type> <Domain> <Port> <HostFQDN> <HostIP> [TXT...]
# shellcheck disable=SC2086
exec dns-sd -P "$INSTANCE" "$SERVICE" local "$PORT" "$HOST" "$LAN_IP" $TXT
