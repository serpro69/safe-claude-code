#!/bin/sh
# Claude Safe Mode - fail-closed wrapper around guard.py
#
# Claude Code treats a hook that exits with any code other than 0 or 2 as a
# non-blocking error and lets the tool call through. This wrapper turns every
# failure path into exit 2, so a missing or broken Python never silently
# disables the guard.

GUARD_DIR="/usr/local/claude-guard"
GUARD_PY="$GUARD_DIR/guard.py"

fail_closed() {
    printf 'Blocked by Claude Safe Mode: the safety check could not run (%s).\n' "$1" >&2
    printf 'Refusing the tool call rather than running it unchecked. Tell the user to run verify.sh.\n' >&2
    exit 2
}

[ -f "$GUARD_PY" ] || fail_closed "guard.py is missing"

# Prefer absolute, system-owned interpreters over whatever is first on PATH.
PY=""
for candidate in /usr/bin/python3 /opt/homebrew/bin/python3 /usr/local/bin/python3; do
    if [ -x "$candidate" ] && "$candidate" -c 'import sys' >/dev/null 2>&1; then
        PY="$candidate"
        break
    fi
done
[ -n "$PY" ] || PY="$(command -v python3 2>/dev/null)"
[ -n "$PY" ] || fail_closed "no working python3 interpreter was found"

"$PY" "$GUARD_PY"
rc=$?
case "$rc" in
    0|2) exit "$rc" ;;
    *)   fail_closed "guard.py exited with code $rc" ;;
esac
