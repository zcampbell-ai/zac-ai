#!/bin/sh
#
# Stops (if loaded) and removes the D025 LaunchAgent installed by
# service-install.sh. Safe to run even if the service was never installed
# or is not currently loaded. See DECISIONS.md D025.

set -u

LABEL="com.zacai.service"
DEST="$HOME/Library/LaunchAgents/$LABEL.plist"
DOMAIN="gui/$(id -u)/$LABEL"

if launchctl print "$DOMAIN" >/dev/null 2>&1; then
    echo "service-uninstall: stopping $LABEL"
    launchctl bootout "$DOMAIN" 2>/dev/null
fi

if [ -f "$DEST" ]; then
    rm "$DEST"
    echo "service-uninstall: removed $DEST"
else
    echo "service-uninstall: $DEST not present - nothing to remove"
fi
