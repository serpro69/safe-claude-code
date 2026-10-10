#!/bin/sh
# Claude Safe Mode - fail-closed wrapper around guard.py
#
# Claude Code treats a hook that exits with any code other than 0 or 2 as a
# non-blocking error and lets the tool call through (unless the hook entry
# sets onFailure: "block", which needs Claude Code 2.1.295 or later). This
# wrapper turns every failure path into exit 2, so a missing or broken Python
# never silently disables the guard.
#
# The interpreter runs in isolated mode (-I): PYTHONPATH, PYTHONHOME,
# PYTHONSTARTUP and the user site-packages directory are all ignored, so
# nothing the user - or a repository the user cloned - can write is imported
# into the guard. Only absolute, system-owned interpreter paths are tried;
# PATH is never consulted.

GUARD_DIR="/usr/local/claude-guard"
GUARD_PY="$GUARD_DIR/guard.py"
INTERPRETERS="/usr/bin/python3 /opt/homebrew/bin/python3 /usr/local/bin/python3"

fail_closed() {
    printf 'Blocked by Claude Safe Mode: the safety check could not run (%s).\n' "$1" >&2
    printf 'Refusing the tool call rather than running it unchecked. Tell the user to run verify.sh.\n' >&2
    exit 2
}

[ -f "$GUARD_PY" ] || fail_closed "guard.py is missing"

# Read the tool call once, so it can be handed to the next interpreter if the
# first one turns out not to work. The trailing x keeps the shell from
# stripping newlines off the end.
payload=$(cat; printf x)
payload=${payload%x}

tried=""
for candidate in $INTERPRETERS; do
    [ -x "$candidate" ] || continue
    tried="$tried $candidate"
    printf '%s' "$payload" | "$candidate" -I "$GUARD_PY"
    rc=$?
    case "$rc" in
        0|2) exit "$rc" ;;
    esac
    # Any other code: if the interpreter itself does not work (for example the
    # macOS stub that only offers to install the developer tools), try the
    # next one. If it works, the guard crashed, and that must block.
    if "$candidate" -I -c 'import sys' >/dev/null 2>&1; then
        fail_closed "guard.py exited with code $rc under $candidate"
    fi
done
fail_closed "no working python3 interpreter was found (tried:${tried:- none})"
