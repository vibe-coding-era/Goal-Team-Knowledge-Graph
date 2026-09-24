#!/usr/bin/env bash
# Install (or remove) a user launchd agent that runs the pipeline on a schedule.
#
# This is the only "automatic" mechanism GTKG has, and it lives entirely outside
# the product: GTKG ships no daemon and no watcher by design. launchd calls
# gtkg-pipeline.sh, which walks the configured workspaces.
#
# Usage: install-launchd.sh <install|uninstall|status> [workspace-root]
set -euo pipefail

ACTION="${1:-install}"
ROOT="${2:-${GTKG_ROOT:-$HOME/gtkg}}"
LABEL="com.gtkg.pipeline"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PIPELINE="$HERE/gtkg-pipeline.sh"

case "$ACTION" in
  status)
    launchctl print "gui/$(id -u)/$LABEL" 2>/dev/null | head -20 \
      || echo "not loaded"
    exit 0
    ;;
  uninstall)
    launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
    rm -f "$PLIST"
    echo "removed $LABEL"
    exit 0
    ;;
  install) ;;
  *) echo "usage: install-launchd.sh <install|uninstall|status> [workspace-root]" >&2; exit 2 ;;
esac

mkdir -p "$ROOT/logs" "$HOME/Library/LaunchAgents"
chmod +x "$PIPELINE"

# The API key never goes in the plist. gtkg-pipeline.sh sources $ROOT/.env, which
# this script creates with 0600 if it does not exist.
if [ ! -f "$ROOT/.env" ]; then
  ( umask 077; cat > "$ROOT/.env" <<'ENV'
# GTKG pipeline environment. Keep this file mode 0600.
# DEEPSEEK_API_KEY=
ENV
  )
  chmod 600 "$ROOT/.env"
  echo "==> created $ROOT/.env (mode 0600) - add DEEPSEEK_API_KEY there"
fi

cat > "$PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>$PIPELINE</string>
    <string>$ROOT</string>
    <string>all</string>
  </array>
  <!-- Every 6 hours. Use StartCalendarInterval instead for a fixed daily slot. -->
  <key>StartInterval</key>
  <integer>21600</integer>
  <key>RunAtLoad</key>
  <false/>
  <key>WorkingDirectory</key>
  <string>$ROOT</string>
  <key>StandardOutPath</key>
  <string>$ROOT/logs/launchd.out.log</string>
  <key>StandardErrorPath</key>
  <string>$ROOT/logs/launchd.err.log</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>GTKG_ROOT</key>
    <string>$ROOT</string>
    <key>PATH</key>
    <string>$HOME/.local/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin</string>
  </dict>
</dict>
</plist>
PLIST

launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
# bootstrap takes the DOMAIN (gui/<uid>) plus the plist path; bootout takes
# the SERVICE target (gui/<uid>/<label>). Mixing them prints launchctl usage.
launchctl bootstrap "gui/$(id -u)" "$PLIST"
launchctl enable "gui/$(id -u)/$LABEL" 2>/dev/null || true

echo "==> installed $PLIST"
launchctl print "gui/$(id -u)/$LABEL" 2>/dev/null | grep -E 'state|program|run interval' || true
echo "==> run it now:   launchctl kickstart -p gui/$(id -u)/$LABEL"
echo "==> uninstall:    $HERE/install-launchd.sh uninstall"
