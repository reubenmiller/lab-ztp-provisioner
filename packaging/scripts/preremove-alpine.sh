#!/bin/sh
# Pre-remove script for ztp-agent on Alpine Linux (OpenRC).
# Called by apk before the package files are removed.
set -e

if command -v rc-service >/dev/null 2>&1; then
    rc-service ztp-agent stop 2>/dev/null || true
fi
if command -v rc-update >/dev/null 2>&1; then
    rc-update del ztp-agent default 2>/dev/null || true
fi
