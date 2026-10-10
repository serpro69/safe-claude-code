#!/bin/bash
#
# Claude Safe Mode - uninstaller (macOS)
#
# Removes the managed policy and the guard script. Your file backups in
# ~/.claude-safe-backups are left in place.
#
# Usage:  sudo ./uninstall.sh
#
set -euo pipefail

MANAGED_FILE="/Library/Application Support/ClaudeCode/managed-settings.json"
GUARD_DIR="/usr/local/claude-guard"

say() { printf '\033[1;34m==>\033[0m %s\n' "$1"; }
ok()  { printf '\033[1;32m  ok\033[0m %s\n' "$1"; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$1" >&2; exit 1; }

[ "$(id -u)" = "0" ] || die "Please run with sudo:  sudo ./uninstall.sh"

if [ -f "$MANAGED_FILE" ]; then
    BACKUP="$MANAGED_FILE.removed.$(date +%Y%m%d-%H%M%S)"
    cp "$MANAGED_FILE" "$BACKUP"
    rm -f "$MANAGED_FILE"
    ok "removed the managed policy (a copy is at $BACKUP)"
else
    say "no managed policy found"
fi

if [ -d "$GUARD_DIR" ]; then
    rm -rf "$GUARD_DIR"
    ok "removed the guard script"
else
    say "no guard script found"
fi

cat <<EOF

$(printf '\033[1;32mClaude Safe Mode has been removed.\033[0m')

Your file backups are still in  ~/.claude-safe-backups  if you want them.
Restart Claude Code / VS Code for the change to take effect.
EOF
