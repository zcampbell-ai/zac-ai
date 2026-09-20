#!/bin/sh
#
# Renders the D025 LaunchAgent template (deploy/com.zacai.service.plist)
# into ~/Library/LaunchAgents with this repo's real, absolute path, and
# creates the log directory launchd will write to. See DECISIONS.md D025.
#
# Deliberately does NOT run `launchctl bootstrap` - loading/starting the
# service is a separate, deliberate step the operator runs themselves
# (printed below), never automated by this script.

set -eu

REPO_DIR=$(cd "$(dirname "$0")/.." && pwd)
TEMPLATE="$REPO_DIR/deploy/com.zacai.service.plist"
LABEL="com.zacai.service"
DEST_DIR="$HOME/Library/LaunchAgents"
DEST="$DEST_DIR/$LABEL.plist"
LOG_DIR="$HOME/Library/Logs/zacai"

if [ ! -f "$TEMPLATE" ]; then
    echo "service-install: template not found at $TEMPLATE" >&2
    exit 1
fi

if [ ! -x "$REPO_DIR/.venv/bin/zacai" ]; then
    echo "service-install: $REPO_DIR/.venv/bin/zacai not found - run 'uv sync' first." >&2
    exit 1
fi

mkdir -p "$DEST_DIR" "$LOG_DIR"

sed \
    -e "s#__ZACAI_REPO_PATH__#$REPO_DIR#g" \
    -e "s#__ZACAI_LOG_DIR__#$LOG_DIR#g" \
    "$TEMPLATE" > "$DEST"

echo "service-install: wrote $DEST"
echo "service-install: next steps (run these yourself - not automated):"
echo "  plutil -lint \"$DEST\""
echo "  launchctl bootstrap gui/\$(id -u) \"$DEST\""
echo "  curl http://127.0.0.1:8000/health"
