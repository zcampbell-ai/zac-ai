#!/bin/sh
#
# Reports whether the D025 LaunchAgent is loaded/running and whether the
# app is answering its health check. Read-only - makes no changes.
# See DECISIONS.md D025.

set -u

LABEL="com.zacai.service"
DOMAIN="gui/$(id -u)/$LABEL"

echo "--- launchctl ---"
if ! launchctl print "$DOMAIN" 2>/dev/null; then
    echo "$LABEL is not loaded"
fi

echo "--- health ---"
if curl -sf http://127.0.0.1:8000/health; then
    echo
else
    echo "no response from http://127.0.0.1:8000/health"
fi
