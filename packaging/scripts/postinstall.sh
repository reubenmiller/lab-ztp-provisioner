#!/bin/sh
# Post-install script for ztp-agent package.
# Called by the package manager after the package files are placed.
set -e

systemctl daemon-reload || true

# Enable the service so it runs on the next (and every subsequent) boot,
# but do NOT start it immediately — the operator may still want to edit
# /etc/default/ztp-agent or place /etc/ztp/server.pub before the first run.
systemctl enable ztp-agent.service

echo "ztp-agent installed."
echo "  Config : /etc/default/ztp-agent"
echo "  Pubkey : /etc/ztp/server.pub  (optional, enables strict trust)"
echo "  Logs   : journalctl -u ztp-agent"
echo ""
echo "To provision now:  systemctl start ztp-agent.service"
echo "To re-provision :  rm -f /var/lib/ztp/provisioned && systemctl restart ztp-agent.service"
