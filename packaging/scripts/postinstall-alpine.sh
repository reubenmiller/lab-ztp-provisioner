#!/bin/sh
# Post-install script for ztp-agent on Alpine Linux (OpenRC).
# Called by apk after the package files are placed.
set -e

if command -v rc-update >/dev/null 2>&1; then
    rc-update add ztp-agent default 2>/dev/null || true
fi

echo "ztp-agent installed."
echo "  Config : /etc/ztp/agent.toml"
echo "  Pubkey : /etc/ztp/server.pub  (optional, enables strict trust)"
echo "  Logs   : /var/log/ztp/agent.log"
echo ""
echo "To provision now : rc-service ztp-agent start"
echo "To re-provision  : rm -f /var/lib/ztp/provisioned && rc-service ztp-agent start"
