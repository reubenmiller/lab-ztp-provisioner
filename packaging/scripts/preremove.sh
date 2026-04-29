#!/bin/sh
# Pre-remove script for ztp-agent package.
# Called by the package manager before the package files are removed.
set -e

systemctl disable --now ztp-agent.service 2>/dev/null || true
