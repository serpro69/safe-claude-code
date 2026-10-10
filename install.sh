#!/bin/bash
#
# Claude Safe Mode - installer (macOS)
#
# Installs a locked-down Claude Code policy that:
#   * turns on the OS sandbox (Seatbelt) so shell commands can only touch the
#     project folder and a short list of research websites,
#   * denies every destructive command and file edit through managed settings,
#   * runs a fail-closed guard script before every command and file edit,
#   * keeps automatic backups of every file Claude changes.
#
# The policy goes in the root-owned managed-settings location, so a Claude
# session cannot edit its own guardrails.
#
# Usage:   sudo ./install.sh
#
set -euo pipefail

MANAGED_DIR="/Library/Application Support/ClaudeCode"
MANAGED_FILE="$MANAGED_DIR/managed-settings.json"
GUARD_DIR="/usr/local/claude-guard"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

say()  { printf '\033[1;34m==>\033[0m %s\n' "$1"; }
ok()   { printf '\033[1;32m  ok\033[0m %s\n' "$1"; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$1" >&2; exit 1; }

# --- preconditions ---------------------------------------------------------
[ "$(uname)" = "Darwin" ] || die "This installer is for macOS. On Linux the managed path is /etc/claude-code/."
[ "$(id -u)" = "0" ] || die "Please run with sudo:  sudo ./install.sh"

# The guard runs under one of these system interpreters in isolated mode
# (python3 -I). On a Mac without the Command Line Tools, /usr/bin/python3 is a
# stub that only offers to install them, so each candidate is actually run.
PYTHON=""
for c in /usr/bin/python3 /opt/homebrew/bin/python3 /usr/local/bin/python3; do
    if [ -x "$c" ] && "$c" -I -c 'import sys' >/dev/null 2>&1; then
        PYTHON="$c"
        break
    fi
done
[ -n "$PYTHON" ] || die "no working python3 was found at /usr/bin, /opt/homebrew/bin or /usr/local/bin. On macOS run 'xcode-select --install' first."
ok "found a working python3 at $PYTHON"

if command -v claude >/dev/null 2>&1; then
    ok "found claude on PATH"
    # A hook that fails to start only blocks the tool call on Claude Code
    # 2.1.295 or later (onFailure: "block"). guard.sh cannot help there,
    # because it is the thing that failed to start.
    CC_VERSION="$(claude --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
    if [ -n "$CC_VERSION" ] && ! "$PYTHON" -I -c 'import sys; v = tuple(int(x) for x in sys.argv[1].split(".")); sys.exit(0 if v >= (2, 1, 295) else 1)' "$CC_VERSION"; then
        say "warning: Claude Code $CC_VERSION is older than 2.1.295. On that version a guard that fails to start lets the command through. Update Claude Code."
    fi
else
    say "note: 'claude' is not on PATH yet. Install the CLI or the VS Code extension before first use."
fi

[ -f "$SRC_DIR/managed-settings.json" ] || die "managed-settings.json not found next to this script."
[ -f "$SRC_DIR/hooks/guard.py" ] || die "hooks/guard.py not found next to this script."
[ -f "$SRC_DIR/hooks/guard.sh" ] || die "hooks/guard.sh not found next to this script."

# --- run the guard's own test suite before trusting it ---------------------
if [ -f "$SRC_DIR/tests/test_guard.py" ]; then
    say "Running the guard test suite"
    if TEST_OUTPUT="$("$PYTHON" -I "$SRC_DIR/tests/test_guard.py" 2>&1)"; then
        ok "$(printf '%s\n' "$TEST_OUTPUT" | grep '^passed:' | tail -1)"
    else
        printf '%s\n' "$TEST_OUTPUT" | tail -40 >&2
        die "the guard test suite failed. Not installing."
    fi
fi

# --- validate the policy JSON before installing it -------------------------
say "Validating the policy file"
"$PYTHON" -c "import json,sys; json.load(open(sys.argv[1]))" "$SRC_DIR/managed-settings.json" \
    || die "managed-settings.json is not valid JSON. Not installing."
ok "policy JSON is valid"

# --- install the guard -----------------------------------------------------
say "Installing the guard script to $GUARD_DIR"
install -d -o root -g wheel -m 755 "$GUARD_DIR"
install -o root -g wheel -m 755 "$SRC_DIR/hooks/guard.py" "$GUARD_DIR/guard.py"
install -o root -g wheel -m 755 "$SRC_DIR/hooks/guard.sh" "$GUARD_DIR/guard.sh"
ok "guard installed, owned by root, world-readable, not user-writable"

# --- self-test the guard before trusting it --------------------------------
say "Self-testing the guard"
BLOCKED_RC=0
printf '%s' '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' \
    | "$GUARD_DIR/guard.sh" >/dev/null 2>&1 || BLOCKED_RC=$?
[ "$BLOCKED_RC" = "2" ] || die "guard did not block 'rm -rf /' (exit $BLOCKED_RC). Aborting."
ALLOWED_RC=0
printf '%s' '{"tool_name":"Bash","tool_input":{"command":"ls -la"}}' \
    | "$GUARD_DIR/guard.sh" >/dev/null 2>&1 || ALLOWED_RC=$?
[ "$ALLOWED_RC" = "0" ] || die "guard wrongly blocked 'ls -la' (exit $ALLOWED_RC). Aborting."
ok "guard blocks destructive commands and allows safe ones"

# --- back up any existing managed policy -----------------------------------
if [ -f "$MANAGED_FILE" ]; then
    BACKUP="$MANAGED_FILE.backup.$(date +%Y%m%d-%H%M%S)"
    cp "$MANAGED_FILE" "$BACKUP"
    ok "backed up the existing policy to $BACKUP"
fi

# --- install the policy ----------------------------------------------------
say "Installing the managed policy to $MANAGED_FILE"
install -d -o root -g wheel -m 755 "$MANAGED_DIR"
# World-readable is required: Claude Code silently skips a managed file it
# cannot read, which would leave the machine unprotected.
install -o root -g wheel -m 644 "$SRC_DIR/managed-settings.json" "$MANAGED_FILE"
ok "policy installed, owned by root, world-readable (0644)"

# --- backups directory for the user ----------------------------------------
REAL_USER="${SUDO_USER:-$(stat -f '%Su' /dev/console)}"
if [ -n "$REAL_USER" ] && [ "$REAL_USER" != "root" ]; then
    USER_HOME="$(eval echo "~$REAL_USER")"
    BK="$USER_HOME/.claude-safe-backups"
    install -d -o "$REAL_USER" -m 700 "$BK" 2>/dev/null || true
    ok "created automatic-backup folder at $BK"
fi

cat <<EOF

$(printf '\033[1;32mClaude Safe Mode is installed.\033[0m')

What changed:
  * Managed policy:  $MANAGED_FILE
  * Guard script:    $GUARD_DIR/
  * File backups:    ~/.claude-safe-backups/  (kept 30 days)

Next steps:
  1. Close every open Claude Code window or VS Code window and reopen it.
     The policy is read when Claude Code starts.
  2. In a session, run  /status  and confirm it shows a managed-settings
     source. Or run  claude doctor  in a terminal.
  3. Run  ./verify.sh  to confirm the guardrails are live.

To remove it later:  sudo ./uninstall.sh
EOF
