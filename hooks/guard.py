#!/usr/bin/env python3
"""
Claude Safe Mode - PreToolUse guard.

Runs before every Bash / PowerShell / Monitor command and before every file
edit. It inspects the full text of the command, not just the first word, so it
also catches forms that permission rules miss: `/bin/rm`, `'rm'`, `sh -c 'rm -rf ~'`,
`curl ... | /bin/sh`, `bash -c "$(curl ...)"`, `python3 - <<EOF ... EOF`,
`r'm'`, `python -c "shutil.rmtree(...)"`, scripts on disk that a command is
about to execute (including after a `cd`), Makefile targets, npm scripts, and
notebook shell cells.

Contract with Claude Code:
  exit 0  -> allow (the tool call continues through the normal permission flow)
  exit 2  -> BLOCK the tool call; stderr is shown to Claude as the reason

The script is fail-closed: an unexpected error, a tool call that cannot be
read, or a script that cannot be inspected all block the tool call.

It also snapshots every file Claude is about to modify into
~/.claude-safe-backups/ so an unwanted edit can always be recovered. A backup
that fails never blocks the edit, but it is reported to the user.

Checks raise `Blocked`; only the entry point at the bottom turns that into an
exit code, so the checks can be exercised in-process by the test suite.
"""

import filecmp
import json
import os
import re
import shutil
import sys
import traceback
from datetime import datetime, timedelta
from pathlib import Path
from typing import NoReturn

# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------
BACKUP_ROOT = Path.home() / ".claude-safe-backups"
BACKUP_MAX_BYTES = 25 * 1024 * 1024
BACKUP_KEEP_DAYS = 30
BACKUP_ERROR_FILE = "LAST_ERROR"          # written inside BACKUP_ROOT when a backup fails
SCRIPT_SCAN_MAX_BYTES = 64 * 1024 * 1024  # a script larger than this is refused, never skipped
SCRIPT_HEAD_BYTES = 200                   # how much of a file to read to find a shebang
MAKE_MAX_DEPTH = 3                        # prerequisite / nested-script recursion limit

BASH_TOOLS = ("Bash", "PowerShell", "Monitor")
FILE_TOOLS = ("Edit", "Write", "NotebookEdit", "MultiEdit")


# ---------------------------------------------------------------------------
# Blocking
# ---------------------------------------------------------------------------
class Blocked(Exception):
    """Raised by any check that decides the tool call must not run."""

    def __init__(self, title, detail=""):
        Exception.__init__(self, title)
        self.title = title
        self.detail = detail

    def message(self):
        lines = ["Blocked by Claude Safe Mode: " + self.title]
        if self.detail:
            lines += ["", self.detail]
        lines += [
            "",
            "This computer is configured to refuse destructive operations. Do not "
            "retry the same thing in a different form. Explain to the user what you "
            "wanted to do and why, and let them do it themselves if they decide it "
            "is safe.",
        ]
        return "\n".join(lines) + "\n"


def block(title, detail="") -> NoReturn:
    raise Blocked(title, detail)


# ---------------------------------------------------------------------------
# Programs that are never allowed, at any path, in any quoting.
#
# HIGH_SIGNAL names are unambiguous program names. They are refused wherever
# they appear as a bare word, which is what catches `sh -c 'rm -rf ~'`.
#
# LOW_SIGNAL names are also ordinary English words ("security", "trash",
# "gpt"), so they are refused only in command position, where they would be
# executed. `grep security thesis.tex` is fine; `security dump-keychain` is not.
# ---------------------------------------------------------------------------
HIGH_SIGNAL = {
    "rm": "deletes files",
    "rmdir": "deletes directories",
    "unlink": "deletes a file",
    "shred": "irreversibly destroys file contents",
    "srm": "securely deletes files",
    "rimraf": "deletes files and directories",
    "diskutil": "partitions, erases and reformats disks",
    "mkfs": "formats a filesystem",
    "newfs": "formats a filesystem",
    "newfs_hfs": "formats a filesystem",
    "newfs_apfs": "formats a filesystem",
    "fdisk": "rewrites partition tables",
    "hdiutil": "creates, erases and unmounts disk images",
    "tmutil": "controls Time Machine and can delete your backups",
    "sudo": "runs commands as the administrator",
    "sudoedit": "edits files as the administrator",
    "doas": "runs commands as another user",
    "launchctl": "loads and unloads background services",
    "systemsetup": "changes system configuration",
    "csrutil": "changes System Integrity Protection",
    "spctl": "changes Gatekeeper security policy",
    "nvram": "writes firmware variables",
    "kextload": "loads a kernel extension",
    "kextunload": "unloads a kernel extension",
    "softwareupdate": "installs system updates",
    "scutil": "changes network and system configuration",
    "pmset": "changes power management settings",
    "mdutil": "changes Spotlight indexing",
    "killall": "kills every process with a given name",
    "pkill": "kills processes by pattern",
    "chown": "changes file ownership",
    "chgrp": "changes file group ownership",
    "chflags": "changes file flags, including the locked flag",
    "dscl": "reads and edits user accounts",
    "crontab": "installs scheduled background jobs",
    "atrm": "manages scheduled jobs",
    "osascript": "runs AppleScript and can drive other applications",
    "automator": "runs Automator workflows",
    "claude": "would start a nested Claude Code session outside these rules",
}

LOW_SIGNAL = {
    "su": "switches to another user account",
    "dd": "writes raw data to disks and can destroy a drive",
    "gpt": "rewrites partition tables",
    "asr": "block-copies and erases volumes",
    "trash": "moves files to the Trash",
    "bless": "changes the boot volume",
    "halt": "halts the machine",
    "shutdown": "shuts the machine down",
    "reboot": "restarts the machine",
    "purge": "forces the system to drop its disk cache",
    "security": "reads and edits the macOS Keychain",
    "at": "schedules background jobs",
    "parallel": "runs arbitrary commands over many inputs at once",
}

ALL_BANNED = dict(HIGH_SIGNAL)
ALL_BANNED.update(LOW_SIGNAL)

# Words that precede the real command and should be skipped when working out
# what is actually being executed.
WRAPPERS = {
    "env", "nohup", "time", "nice", "ionice", "caffeinate", "stdbuf", "command",
    "builtin", "exec", "xargs", "noglob", "nocorrect", "setsid", "flock",
    "watch", "timeout", "then", "do", "else", "elif", "if", "while", "until",
    "busybox", "toybox",
}

# Options of wrapper programs that consume the following word, so that the
# real command is not mistaken for an option value (`nice -n 10 dd ...`).
WRAPPER_OPTIONS_WITH_ARG = {
    "timeout": {"-s", "--signal", "-k", "--kill-after"},
    "nice": {"-n", "--adjustment"},
    "ionice": {"-c", "--class", "-n", "--classdata", "-p", "--pid"},
    "env": {"-u", "--unset", "-C", "--chdir", "-S", "--split-string"},
    "xargs": {"-I", "-i", "-n", "-P", "-d", "-a", "-L", "-s", "-E", "--max-args",
              "--max-procs", "--delimiter", "--arg-file", "--max-lines",
              "--max-chars", "--eof", "--replace"},
    "watch": {"-n", "--interval"},
    "flock": {"-w", "--timeout", "-E", "--conflict-exit-code"},
    "stdbuf": {"-i", "-o", "-e", "--input", "--output", "--error"},
    "caffeinate": {"-t", "-w"},
}
# Wrapper programs whose first non-option word is an operand, not the command.
WRAPPER_POSITIONAL = {"timeout": 1, "flock": 1}

SHELLS = {"sh", "bash", "zsh", "ksh", "dash", "ash", "fish", "csh", "tcsh"}
INTERPRETERS = {
    "python", "python2", "python3", "pythonw", "perl", "ruby", "node", "deno",
    "bun", "osascript", "rscript", "r", "php", "lua", "julia",
}
DOWNLOADERS = {"curl", "wget", "fetch"}
RUNNERS = SHELLS | INTERPRETERS | {"source", ".", "exec", "make", "gmake", "env"}

# ---------------------------------------------------------------------------
# Pattern rules: (regex, title, explanation).
#
# PATTERN_RULES run on the command with quoted prose removed, so a commit
# message that mentions "clean up" does not trip the `git clean` rule.
# PATH_RULES and RAW_RULES run on the command with quote characters stripped,
# so a quoted path such as "~/Library/Application Support/..." is still seen.
# ---------------------------------------------------------------------------
CASE_SENSITIVE = re.RegexFlag(0)


def _r(pattern, flags=re.IGNORECASE):
    return re.compile(pattern, flags)


# `git`, its global options (including the ones that take a separate
# argument, such as `-C dir` or `--work-tree dir`), then the subcommand.
GIT = (r"\bgit\s+(?:(?:-C|--git-dir|--work-tree|--namespace|--exec-path|--super-prefix|-c)\s+\S+\s+"
       r"|-[^\s]+\s+)*")

PATTERN_RULES = [
    # downloading and executing code (pipes are handled by check_download_pipelines)
    (_r(r"<\s*\(\s*(curl|wget|fetch)\b"),
     "executing a download through process substitution",
     "`bash <(curl ...)` runs code from the internet without anyone reading it first."),
    (_r(r"\beval\b"),
     "eval",
     "`eval` runs generated text as code."),

    # git: anything that rewrites history or discards work
    (_r(GIT + r"push\b[^\n]*(--force\b|--force-with-lease\b|--force-if-includes\b|\s-f\b|--delete\b|\s-d\b|--mirror\b|\s\+\S|\s:\S)"),
     "force pushing or deleting a remote branch",
     "This rewrites or removes history on the remote and can destroy work that only exists there."),
    (_r(GIT + r"reset\b[^\n]*--(hard|merge)\b"),
     "git reset --hard",
     "This permanently discards every uncommitted change."),
    (_r(GIT + r"clean\b"),
     "git clean",
     "This permanently deletes untracked files, which often includes data and notes that were never committed."),
    (_r(GIT + r"checkout\b[^\n]*(\s--(\s|$)|\s\.(\s|$)|\s-f\b|--force\b|\s-B\b|--orphan\b)"),
     "git checkout that discards changes",
     "This throws away uncommitted edits."),
    # `git restore --staged` only un-stages and is allowed; anything that touches
    # the working tree (the default, --worktree / -W, or --source / -s) is not.
    # Compiled case-sensitively: -S (staged) and -s (source) are different flags.
    (_r(GIT + r"restore\b(?![^\n]*(?:--staged\b|\s-S\b))", CASE_SENSITIVE),
     "git restore",
     "This throws away uncommitted edits. Only `git restore --staged <file>` (un-staging) is allowed."),
    (_r(GIT + r"restore\b[^\n]*(?:--worktree\b|\s-W\b|--source\b|\s-s\b)", CASE_SENSITIVE),
     "git restore",
     "This throws away uncommitted edits. Only `git restore --staged <file>` (un-staging) is allowed."),
    (_r(GIT + r"(filter-branch|filter-repo|replace)\b"),
     "rewriting git history",
     "This rewrites commits across the repository."),
    (_r(GIT + r"rebase\b"),
     "git rebase",
     "Rebasing rewrites history and can lose commits if it goes wrong."),
    (_r(GIT + r"commit\b[^\n]*--amend\b"),
     "amending a commit",
     "This rewrites the previous commit."),
    (_r(GIT + r"branch\b[^\n]*(\s-[a-zA-Z]*D\b|\s-d\b|--delete\b|\s-M\b|\s-f\b|--force\b)"),
     "deleting or force-renaming a git branch",
     "Deleting a branch can orphan commits."),
    (_r(GIT + r"tag\b[^\n]*(\s-d\b|--delete\b|\s-f\b|--force\b)"),
     "deleting or overwriting a git tag",
     "Tags mark released or submitted versions."),
    (_r(GIT + r"reflog\b[^\n]*\b(expire|delete)\b"),
     "expiring the git reflog",
     "The reflog is what makes most git mistakes recoverable."),
    (_r(GIT + r"(gc|prune|prune-packed|repack)\b"),
     "pruning git objects",
     "This destroys the objects that `git reflog` would otherwise recover."),
    (_r(GIT + r"stash\b[^\n]*\b(drop|clear)\b"),
     "dropping stashed changes",
     "Stashed work is not recoverable once dropped."),
    (_r(GIT + r"update-ref\b[^\n]*\s-d\b"),
     "deleting a git ref", "This deletes a branch or tag pointer directly."),
    (_r(GIT + r"worktree\b[^\n]*\b(remove|prune)\b"),
     "removing a git worktree", "This deletes a working copy and anything uncommitted in it."),
    (_r(GIT + r"rm\b(?![^\n]*--cached\b)"),
     "git rm",
     "This deletes files from the working tree. Ask the user to remove files themselves."),
    (_r(GIT + r"remote\b[^\n]*\b(remove|rm|set-url|prune)\b"),
     "changing git remotes", "This can disconnect the project from its backup on the server."),
    # Only read-only queries and setting the user's own name/email are allowed.
    (_r(GIT + r"config\b"
        r"(?!\s+(?:--global\s+|--local\s+)?user\.(?:name|email)\s+\S+\s*(?:$|[;&|\n]))"
        r"(?![^\n]*(?:--get\b|--get-all\b|--get-regexp\b|--list\b|\s-l\b))"),
     "changing git configuration",
     "Git configuration can run hooks and aliases. Only `git config --get ...` and "
     "`git config user.name|user.email <value>` are allowed."),
    # Compiled case-sensitively: `-C dir` is harmless and handled by the GIT prefix.
    (_r(GIT + r"(?:-c\s|--exec-path\b)", CASE_SENSITIVE),
     "git with an inline config or exec-path override",
     "`git -c` and `git --exec-path` can point git at a script to run."),
    (_r(GIT + r"submodule\b[^\n]*\bdeinit\b"),
     "removing a git submodule", "This deletes the submodule's working copy."),

    # find / xargs / fd deletion
    (_r(r"\bfind\b[^\n]*\s-delete\b"), "find -delete", "This deletes every file the search matches."),
    (_r(r"\bfind\b[^\n]*\s-(exec|execdir|ok|okdir)\b"), "find -exec",
     "`find -exec` runs an arbitrary command once per matched file."),
    (_r(r"\bfd\b[^\n]*\s(-x|-X|--exec|--exec-batch)\b"), "fd --exec",
     "This runs an arbitrary command once per matched file."),

    # permissions
    (_r(r"\bchmod\b[^\n]*(\s-[a-zA-Z]*R\b|--recursive\b)"), "recursive permission change",
     "Changing permissions across a whole tree can break your account or expose private files."),
    (_r(r"\bchmod\b[^\n]*\s(0?777|0?666|a\+w|o\+w|[ugoa]*\+[rw]*x[rw]*)\b"),
     "chmod that makes files executable or world-writable",
     "Scripts do not need to be executable here; run them with `python script.py` or `bash script.sh`."),

    # overwriting, truncating, moving away
    (_r(r"\bmv\b[^\n]*\s/dev/null\b"), "moving a file to /dev/null", "This destroys the file."),
    (_r(r"\btruncate\b"), "truncate", "This empties files in place."),
    (_r(r"(^|[;&|])\s*:?\s*>\s*[^>\s&]"), "emptying a file with a bare redirect",
     "`> file` or `: > file` erases the file's contents."),
    (_r(r">\|"), "clobbering redirect", "`>|` overrides the shell's overwrite protection."),
    (_r(r"\bsed\b[^\n]*(\s-[a-zA-Z]*[iI]\b|--in-place)"), "sed in-place edit",
     "Use the Edit tool to change files; it keeps a backup and shows a diff."),
    (_r(r"\bperl\b[^\n]*\s-[a-zA-Z]*i\b"), "perl in-place edit",
     "Use the Edit tool to change files; it keeps a backup and shows a diff."),
    (_r(r"\b(gawk|awk)\b[^\n]*\s-i\s*inplace\b"), "awk in-place edit",
     "Use the Edit tool to change files; it keeps a backup and shows a diff."),
    (_r(r"\bsort\b[^\n]*(\s-o\b|--output\b)"), "sort -o", "This overwrites a file in place."),
    (_r(r"\btee\b(?![^\n]*(\s-[a-zA-Z]*a\b|--append\b))"), "tee without -a",
     "`tee file` overwrites the file. Use `tee -a` to append, or the Write tool."),
    (_r(r"\brsync\b[^\n]*--delete"), "rsync --delete",
     "This deletes files in the destination that are missing from the source."),
    (_r(r"\btar\b[^\n]*\s-C\s*/(\s|$)"), "extracting an archive over the filesystem root",
     "This overwrites system files."),
    (_r(r"\btar\b[^\n]*--remove-files"), "tar --remove-files", "This deletes the files after archiving them."),
    (_r(r"\b(gzip|bzip2|xz|zstd|compress)\b(?![^\n]*(\s-[a-zA-Z]*[kc]\b|--keep|--stdout|--to-stdout|--test|--list|\s-t\b|\s-l\b))"),
     "compressing a file in place",
     "`gzip file` deletes the original. Add `-k` to keep it, or `-c` to write to stdout."),
    (_r(r"\b(gunzip|bunzip2|unxz|unzstd|uncompress)\b(?![^\n]*(\s-[a-zA-Z]*[kc]\b|--keep|--stdout|--to-stdout|--test|--list|\s-t\b|\s-l\b))"),
     "decompressing a file in place",
     "This deletes the compressed original. Add `-k` to keep it, or `-c` to write to stdout."),
    (_r(r"\bunzip\b(?![^\n]*\s-[a-zA-Z]*[nltpz]\b)"), "unzip without -n",
     "`unzip` overwrites existing files. Add `-n` so it never overwrites."),
    (_r(r":\s*\(\s*\)\s*\{[^}]*\|[^}]*&[^}]*\}\s*;"), "fork bomb",
     "This pattern spawns processes until the machine locks up."),
    (_r(r"\bkill\b[^\n]*\s-(9|KILL|SIGKILL|s\s*KILL)\b"), "kill -9",
     "Force-killing a process can corrupt whatever it was writing."),

    # launching applications and editor extensions, which run outside the sandbox
    (_r(r"(?:^|[;&|({]\s*)\s*(?:[\w./-]*/)?open\s+[^\n]*"
        r"(?:\s-[ab]\b|\s--(?:bundle|app)\b"
        r"|\.(?:command|app|pkg|mpkg|dmg|sh|bash|zsh|py|rb|pl|scpt|applescript|terminal|workflow|jar)\b)"),
     "opening a file with an application that can run code",
     "`open` hands the file to another application, which then runs outside the sandbox."),
    (_r(r"\bcode\b[^\n]*--install-extension\b"),
     "installing an editor extension", "Extensions run code inside VS Code with your full access."),

    # system-wide package changes
    (_r(r"\bbrew\b[^\n]*\s(install|reinstall|uninstall|remove|rm|upgrade|update|cleanup|autoremove|link|unlink|services|tap|untap|bundle)\b"),
     "changing installed Homebrew packages",
     "Installing or removing system packages changes the whole machine, not just this project. Ask the user to run this themselves."),
    (_r(r"\bnpm\b[^\n]*\s(install|i|add|uninstall|remove|rm|un|link)\b[^\n]*(\s-g\b|--global\b)"),
     "installing an npm package globally", "A global install changes the whole machine."),
    (_r(r"\b(yarn|pnpm|bun)\b[^\n]*\sglobal\b"), "installing a package globally",
     "A global install changes the whole machine."),
    (_r(r"\bpip3?\b[^\n]*--break-system-packages\b"), "overriding Python's system package protection",
     "This can break the Python that macOS and your other tools rely on."),
    (_r(r"\b(pip3?|pipx|uv)\b[^\n]*\suninstall\b"), "uninstalling a Python package",
     "Removing packages can break other projects. Ask the user to do this themselves."),
    (_r(r"\bconda\b[^\n]*\s(remove|uninstall|clean)\b"), "removing conda packages or environments",
     "Removing packages or environments can break other projects."),
    (_r(r"\bconda\b[^\n]*\senv\b[^\n]*\sremove\b"), "removing a conda environment",
     "This deletes an environment other projects may rely on."),
    (_r(r"\bdocker\b[^\n]*\s(rm|rmi|prune|kill|stop|system|volume)\b"), "destructive docker command",
     "This removes or stops containers, images or volumes."),

    # persistence and autostart
    (_r(r"\b(crontab|launchctl)\b"), "scheduling a background job",
     "Scheduled jobs keep running after this conversation ends."),

    # the safety configuration and the permission system
    (_r(r"--dangerously-skip-permissions|dangerouslyDisableSandbox|bypassPermissions|--permission-mode|--allowedTools|--disallowedTools"),
     "trying to change the permission system", "The permission system cannot be changed from inside a session."),
    (_r(r"\bCLAUDE_CODE_[A-Z_]*\s*="), "setting a Claude Code environment variable",
     "These variables change how the safety checks behave."),
    (_r(r"\b(disableAllHooks|allowManagedHooksOnly|disableBypassPermissionsMode|allowUnsandboxedCommands)\b"),
     "editing the safety policy keys", "The safety rules themselves are off limits."),
]

# Run on the command with quotes stripped, so quoted substitutions are seen.
RAW_RULES = [
    (_r(r"(\$\(|`)\s*(curl|wget|fetch)\b"),
     "substituting a download into a command",
     "`$(curl ...)` runs or injects code from the internet without anyone reading it first. "
     "Download to a file with `curl -o` and inspect it instead."),
]

PATH_RULES = [
    (_r(r"LaunchAgents|LaunchDaemons|StartupItems|/etc/periodic"), "touching an autostart folder",
     "Files in these folders run every time the machine starts."),
    (_r(r"(>>?|\btee\b|\bcp\b|\bmv\b|\bln\b|\binstall\b)[^\n]*\.(zshrc|zprofile|zshenv|zlogin|zlogout|bashrc|bash_profile|bash_login|bash_logout|profile|envrc)\b"),
     "writing to a shell startup file",
     "Code in a shell startup file runs every time a terminal opens."),
    (_r(r"(>>?|\btee\b|\bcp\b|\bmv\b|\bln\b|\binstall\b)[^\n]*\.(vscode|idea)/"),
     "writing editor configuration",
     "Editor configuration can point the editor at programs to run outside the sandbox."),
    (_r(r"(^|[\s=:~/])\.(ssh|aws|gnupg|docker|kube|config/gcloud)(/|\s|$)|(^|[\s=:~/])\.(netrc|pypirc)\b"),
     "touching credential files", "These files hold keys and passwords."),
    (_r(r"\bid_(rsa|dsa|ecdsa|ed25519)\b"), "touching an SSH private key", "This is a private key."),
    (_r(r"Keychains?/|\blogin\.keychain|\bkeychain-db\b"), "touching the macOS Keychain",
     "The Keychain holds your saved passwords."),
    (_r(r"\bdefaults\b[^\n]*\s(write|delete|import|rename)\b"), "changing application preferences",
     "This rewrites the preferences of applications on the machine."),
    (_r(r"\bxattr\b[^\n]*(\s-[a-zA-Z]*[cd]\b|--clear|--delete)"), "removing file attributes",
     "This strips quarantine and other protective attributes."),
    (_r(r"managed-settings|/claude-guard(/|$)|com\.anthropic\.claudecode|/ClaudeCode/"),
     "touching the Claude Safe Mode configuration", "The safety rules themselves are off limits."),
    (_r(r"\.claude/settings|\.claude\.json\b|\.mcp\.json\b|\.claude/hooks|\.claude/plugins|\.claude/agents|\.claude/skills|\.claude/commands|\.claude/scheduled_tasks"),
     "touching Claude Code's own settings", "Changing these files could switch the safety rules off."),
    (_r(r"/dev/(r?disk|sd[a-z]|nvme)"), "touching a raw disk device",
     "Writing to a raw disk device destroys the drive's contents."),
    (_r(r"\.git/(hooks|config)\b"), "touching git hooks or config",
     "Git hooks run arbitrary code on every commit."),
    (_r(r"\.?latexmkrc\b|\.Rprofile\b|\.Renviron\b"), "touching a tool startup file",
     "These files run code every time the tool starts."),
    (_r(r"/Library/Python/|/site-packages/|\.ipython/"), "touching Python's startup directories",
     "Code placed there runs every time Python starts, including inside the safety check itself."),
]

# ---------------------------------------------------------------------------
# Inline-script detection
# ---------------------------------------------------------------------------
# An interpreter given its program on the command line.
INLINE_INTERP = re.compile(
    r"\b(?:ba|z|k|da|a)?sh\s+(?:-[A-Za-z]+\s+)*-c\b"
    r"|\b(?:python3?|pythonw|perl|ruby|node|deno|bun|osascript|Rscript|php|lua|julia)\s+(?:-[A-Za-z]+\s+)*-(?:c|e|E|r)\b"
    r"|\bR\s+(?:-[A-Za-z]+\s+)*-e\b"
    r"|\bxargs\b|\bsource\b|(?:^|[\s;&|])\.\s+\S",
    re.IGNORECASE,
)
# An interpreter reading its program from stdin: `python3 - <<EOF`, `bash <<EOF`, `sh < s.sh`.
STDIN_SCRIPT = re.compile(
    r"\b(?:python3?|pythonw|perl|ruby|node|deno|bun|osascript|Rscript|R|php|lua|julia|(?:ba|z|k|da|a)?sh)\b"
    r"(?:\s+-{1,2}[A-Za-z][\w-]*)*\s*(?:-(?:\s|$)|<<|<(?!\())",
    re.IGNORECASE,
)
SUBSTITUTION = re.compile(r"\$\(|`|<\(|>\(")

# Function-level danger inside Python, R, JavaScript, Julia, SQL and notebooks.
# `shutil.move` / `os.rename` are deliberately not listed: renaming inside the
# project is reversible and the false-positive rate on ordinary scripts is high.
SCRIPT_DELETE = re.compile(
    r"shutil\.rmtree|(?<![\w.])rmtree\s*\(|os\.remove\b|os\.unlink\b|os\.rmdir\b|os\.removedirs\b|os\.truncate\b"
    r"|\.unlink\s*\(|\.rmdir\s*\(|send2trash|os\.chmod\b|os\.chown\b"
    r"|\bfile\.remove\s*\(|(?<![\w.])unlink\s*\(|\bfs::(file|dir)_delete\b"
    r"|\bfs\.(rm|rmSync|rmdir|rmdirSync|unlink|unlinkSync)\b|\brimraf\b"
    r"|\bRemove-Item\b|\bDROP\s+(TABLE|DATABASE|SCHEMA)\b|\bTRUNCATE\s+TABLE\b|\bDELETE\s+FROM\b",
    re.IGNORECASE,
)
SCRIPT_SPAWN = re.compile(r"subprocess\.|os\.system\b|os\.popen\b|os\.exec\w*\b|\bsystem\s*\(|\bshell\s*\(")

# Places a script hands a string to a shell. The text after the call is
# checked as if it had been typed at the command line.
SCRIPT_SHELL_CALL = re.compile(
    r"(os\.system|os\.popen|subprocess\.\w+|commands\.getoutput|system|system2|shell|execSync|exec|spawn|spawnSync|run|sh)\s*\(([^\n]{0,400})",
    re.IGNORECASE,
)
NOTEBOOK_BANG = re.compile(r'(?m)^\s*"?\s*[!%]\s*([^\n"]{1,400})')
CELL_SHELL_MAGIC = re.compile(r"^%%(?:bash|sh|script\s+(?:[\w./-]*/)?(?:ba|z|k|da|a)?sh\b|system|sx|!|writefile\b)")

SHELL_EXTENSIONS = {".sh", ".bash", ".zsh", ".ksh", ".command"}
CODE_EXTENSIONS = {
    ".py", ".pyw", ".ipynb", ".r", ".rmd", ".qmd", ".jl", ".js", ".mjs", ".cjs",
    ".ts", ".rb", ".pl", ".pm", ".php", ".lua", ".scpt", ".applescript", ".sql",
}
READ_ONLY_FIRST = {
    "cat", "head", "tail", "less", "more", "grep", "rg", "egrep", "fgrep", "wc",
    "diff", "ls", "stat", "file", "md5", "md5sum", "shasum", "sha256sum", "git",
    "find", "cp", "sort", "uniq", "cut", "awk", "tr", "echo", "printf", "test",
    "mkdir", "touch", "cd", "pwd", "which", "type", "code", "du", "df",
    "tree", "bat", "pandoc", "pdflatex", "xelatex", "lualatex", "latexmk",
    "bibtex", "biber", "jq", "yq", "column", "paste", "join", "comm", "nl",
    "strings", "hexdump", "xxd", "od", "basename", "dirname", "realpath",
    "readlink", "date", "cal", "env", "printenv", "true", "false", "sleep",
    "ln", "mv", "tar", "zip", "unzip", "pip", "pip3", "pipx", "black", "ruff",
    "flake8", "mypy", "pytest", "texcount", "detex", "chktex", "lacheck",
}
# Commands that may look at the backup folder (restore = copy out of it).
BACKUP_READ_ONLY = {
    "ls", "cat", "head", "tail", "less", "more", "diff", "cmp", "find", "cp",
    "stat", "file", "wc", "grep", "rg", "egrep", "fgrep", "tree", "du", "md5",
    "md5sum", "shasum", "sha256sum", "realpath", "basename", "dirname", "echo",
    "printf", "test", "sort", "uniq", "cut", "column", "nl", "strings", "date",
    "true", "cd", "pwd",
}
BACKUP_DIR_NAME = ".claude-safe-backups"

# ---------------------------------------------------------------------------
# Tokenising helpers
# ---------------------------------------------------------------------------
QUOTED = re.compile(r"'[^']*'|\"(?:[^\"\\]|\\.)*\"")
SEGMENT_SPLIT = re.compile(r"\|\||&&|[|;&\n(){}]")
CHAIN_SPLIT = re.compile(r"\|\||&&|[;&\n]")
TOKEN_SPLIT = re.compile(r"[\s;&|()<>{},=\n]+")
PATH_TOKEN_SPLIT = re.compile(r"[\s;&|()<>{}]+")
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
WRITE_TARGET = re.compile(r"(?<![<>])>{1,2}\s*([^\s;|&<>(){}]+)")


def defang(text):
    """
    Remove quoted prose, but keep quoted text that is a single word or is glued
    to a word: a single quoted word is a token, not prose.

    `git commit -m "clean up"`  ->  `git commit -m  Q `
    `r'm' -rf x`                ->  `rm -rf x`
    `'rm' -rf x`                ->  `rm -rf x`
    """
    text = text.replace("\\", "")
    out = []
    i = 0
    for m in QUOTED.finditer(text):
        before = text[m.start() - 1] if m.start() > 0 else " "
        after = text[m.end()] if m.end() < len(text) else " "
        glued = (not before.isspace()) or (not after.isspace())
        inner = m.group(0)[1:-1]
        single_word = not any(ch.isspace() for ch in inner)
        out.append(text[i:m.start()])
        out.append(inner if (glued or single_word) else " Q ")
        i = m.end()
    out.append(text[i:])
    return "".join(out)


def strip_quotes(text):
    return re.sub(r"""['"\\]""", "", text).replace("`", " ")


def unquote_keep_backticks(text):
    """Like strip_quotes, but backticks survive so `...` substitutions are visible."""
    return re.sub(r"""['"\\]""", "", text)


def basename(token):
    tok = token.strip()
    if "/" in tok:
        tok = tok.rsplit("/", 1)[-1]
    return tok


def command_position_tokens(text):
    """Yield the basename of the program each simple command runs."""
    for segment in SEGMENT_SPLIT.split(text):
        words = segment.split()
        i = 0
        while i < len(words):
            w = words[i]
            if ASSIGNMENT.match(w):
                i += 1
                continue
            b = basename(w)
            if b in WRAPPERS and b not in ALL_BANNED:
                i += 1
                takes_arg = WRAPPER_OPTIONS_WITH_ARG.get(b, set())
                while i < len(words) and words[i].startswith("-") and words[i] != "-":
                    opt = words[i]
                    i += 2 if (opt in takes_arg and "=" not in opt) else 1
                i += WRAPPER_POSITIONAL.get(b, 0)
                continue
            yield b
            break


def first_program(text):
    for tok in command_position_tokens(text):
        return tok
    return ""


def substitution_bodies(text):
    """
    Return the text inside `$( )`, backticks, `<( )` and `>( )` with quotes
    stripped, or the whole unquoted command if the nesting cannot be worked out.
    """
    bodies = []
    i, n = 0, len(text)
    while i < n:
        if text.startswith(("$(", "<(", ">("), i):
            depth, j = 0, i + 1
            while j < n:
                if text[j] == "(":
                    depth += 1
                elif text[j] == ")":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            if j >= n:
                return strip_quotes(text)
            bodies.append(text[i + 2:j])
            i = j + 1
            continue
        if text[i] == "`":
            j = text.find("`", i + 1)
            if j < 0:
                return strip_quotes(text)
            bodies.append(text[i + 1:j])
            i = j + 1
            continue
        i += 1
    return strip_quotes(" ; ".join(bodies))


# ---------------------------------------------------------------------------
# Shell-level checks
# ---------------------------------------------------------------------------
def check_banned(text, context=""):
    for raw in TOKEN_SPLIT.split(text):
        tok = basename(raw)
        if tok in HIGH_SIGNAL:
            detail = "`%s` %s." % (tok, HIGH_SIGNAL[tok])
            if context:
                detail += "\n(Found in %s.)" % context
            block("the command uses `%s`" % tok, detail)
    for tok in command_position_tokens(text):
        if tok in ALL_BANNED:
            detail = "`%s` %s." % (tok, ALL_BANNED[tok])
            if context:
                detail += "\n(Found in %s.)" % context
            block("the command runs `%s`" % tok, detail)


def check_rules(rules, text, context=""):
    for rx, title, detail in rules:
        if rx.search(text):
            if context:
                detail += "\n(Found in %s.)" % context
            block(title, detail)


def stage_decodes(stage):
    """True if this pipeline stage produces downloaded or decoded bytes.

    The downloader may sit behind a wrapper or inside `sh -c '...'`, so every
    word of the stage counts, not only the program in command position."""
    names = {basename(w) for w in stage.split()}
    if names & DOWNLOADERS:
        return True
    if "base64" in names and re.search(r"\s(-d|-D|--decode)\b", stage):
        return True
    if "xxd" in names and re.search(r"\s-r\b", stage):
        return True
    if "openssl" in names and re.search(r"\s-d\b", stage):
        return True
    return False


def check_download_pipelines(text, context=""):
    """
    `curl ... | <anything that runs code>`: the program after the pipe is
    resolved by basename and through wrappers, so `| /bin/sh`, `| (bash)` and
    `| env python3` are all seen.
    """
    text = defang(text)
    for chain in CHAIN_SPLIT.split(text):
        seen_source = False
        for stage in chain.split("|"):
            prog = first_program(stage)
            if seen_source and (prog in SHELLS or prog.lower() in INTERPRETERS):
                detail = ("Piping a download or decoded data into `%s` runs code that nobody has read. "
                          "Download to a file with `curl -o` and inspect it instead." % prog)
                if context:
                    detail += "\n(Found in %s.)" % context
                block("piping a download straight into an interpreter", detail)
            if stage_decodes(stage):
                seen_source = True


def check_shell_text(text, context=""):
    """Run every shell-level check against a piece of shell text."""
    check_banned(defang(text), context)
    check_rules(PATTERN_RULES, defang(text), context)
    check_rules(RAW_RULES, unquote_keep_backticks(text), context)
    check_rules(PATH_RULES, strip_quotes(text), context)
    check_download_pipelines(text, context)


def program_index(words):
    """Index of the word that is the program of this simple command, or None."""
    i = 0
    while i < len(words):
        w = words[i]
        if ASSIGNMENT.match(w):
            i += 1
            continue
        b = basename(w)
        if b in WRAPPERS and b not in ALL_BANNED:
            i += 1
            takes_arg = WRAPPER_OPTIONS_WITH_ARG.get(b, set())
            while i < len(words) and words[i].startswith("-") and words[i] != "-":
                opt = words[i]
                i += 2 if (opt in takes_arg and "=" not in opt) else 1
            i += WRAPPER_POSITIONAL.get(b, 0)
            continue
        return i
    return None


def executed_files(words):
    """The files this simple command would execute as a script: the program
    itself, an interpreter's script operand (or stdin redirect), a sourced
    file, or a Makefile named with -f."""
    idx = program_index(words)
    if idx is None:
        return []
    prog = basename(words[idx])
    rest = words[idx + 1:]
    files = [words[idx]]
    if prog in SHELLS or prog.lower() in INTERPRETERS:
        k = 0
        while k < len(rest):
            w = rest[k]
            if w in ("-m", "-c", "-e", "-E", "-r"):
                break
            if w == "<" and k + 1 < len(rest):
                files.append(rest[k + 1])
                break
            if w.startswith("-") and w != "-":
                k += 1
                continue
            if w not in ("-", ">", ">>", "2>"):
                files.append(w)
            break
    elif prog in ("source", "."):
        if rest:
            files.append(rest[0])
    elif prog in ("make", "gmake"):
        for k, w in enumerate(rest):
            if w in ("-f", "--file", "--makefile") and k + 1 < len(rest):
                files.append(rest[k + 1])
    return files


def check_write_then_run(command):
    """
    A file written by this command and then executed by a later part of the
    same command cannot be inspected on disk, so the pair itself is refused.
    """
    text = strip_quotes(command)
    targets = []
    for m in WRITE_TARGET.finditer(text):
        targets.append((m.end(), m.group(1)))
    for m in re.finditer(r"\btee\b((?:\s+-\S+)*)\s+([^\s;|&<>(){}]+)", text):
        targets.append((m.end(), m.group(2)))
    if not targets:
        return
    for pos, target in targets:
        name = basename(target)
        if not name:
            continue
        for segment in SEGMENT_SPLIT.split(text[pos:]):
            words = segment.split()
            if words and any(basename(f) == name for f in executed_files(words)):
                block("writing a script and running it in the same command",
                      "`%s` is written and then executed before it can be inspected. "
                      "Write the file first, then run it as a separate step." % target)


def check_backup_dir(command):
    """Only reading from, or copying out of, the backup folder is allowed."""
    text = strip_quotes(command)
    if BACKUP_DIR_NAME not in text:
        return
    for prog in command_position_tokens(defang(command)):
        if prog not in BACKUP_READ_ONLY:
            block("changing the backup folder",
                  "`%s` would modify ~/%s, which holds the copies that make edits recoverable. "
                  "Only reading from it, or copying files out of it, is allowed." % (prog, BACKUP_DIR_NAME))
    for m in re.finditer(r"(?:^|[;&|]\s*)\s*(?:cp|install|ln)\s+(.+?)(?=$|[;&|\n])", text):
        args = [a for a in m.group(1).split() if not a.startswith("-")]
        if args and BACKUP_DIR_NAME in args[-1]:
            block("writing into the backup folder", "Backups are read-only. Copy files out of the folder, not into it.")
    for m in WRITE_TARGET.finditer(text):
        if BACKUP_DIR_NAME in m.group(1):
            block("writing into the backup folder", "Backups are read-only. Copy files out of the folder, not into it.")


# ---------------------------------------------------------------------------
# Script-file inspection
# ---------------------------------------------------------------------------
def looks_like_shell(path, head):
    if path.suffix.lower() in SHELL_EXTENSIONS:
        return True
    return bool(re.match(r"#!.*\b(ba|z|k|da|a)?sh\b", head))


def looks_like_code(path, head):
    if path.suffix.lower() in CODE_EXTENSIONS:
        return True
    return bool(re.match(r"#!.*\b(python|perl|ruby|node|Rscript|julia|osascript)", head))


def read_head(path):
    try:
        with open(str(path), "rb") as fh:
            return fh.read(SCRIPT_HEAD_BYTES).decode("utf-8", "replace")
    except Exception:
        return None


def read_script_text(path, label):
    """Read a script that is about to run. Anything that cannot be inspected blocks."""
    try:
        size = path.stat().st_size
    except Exception as exc:
        block("a script that cannot be inspected", "`%s` could not be examined (%s)." % (label, exc))
    if size > SCRIPT_SCAN_MAX_BYTES:
        block("a script too large to inspect",
              "`%s` is %d MB; scripts over %d MB are refused rather than run unchecked."
              % (label, size // (1024 * 1024), SCRIPT_SCAN_MAX_BYTES // (1024 * 1024)))
    try:
        return path.read_text(errors="replace")
    except Exception as exc:
        block("a script that cannot be inspected", "`%s` could not be read (%s)." % (label, exc))


def scan_shell_lines(lines, label):
    for line in lines:
        if line.lstrip().startswith("#!"):
            continue
        code = line.split("#", 1)[0]
        if code.strip():
            check_shell_text(code, context=label)


def scan_code_text(text, label):
    m = SCRIPT_DELETE.search(text)
    if m:
        block(
            "running a script that deletes or overwrites files",
            "`%s` contains `%s`. Scripts run here may not delete files. Write outputs "
            "to a new folder instead, or use `tempfile.TemporaryDirectory()` for scratch "
            "space." % (label, m.group(0)),
        )
    for call in SCRIPT_SHELL_CALL.finditer(text):
        check_shell_text(strip_quotes(call.group(2)), context="a shell call in %s" % label)
    for bang in NOTEBOOK_BANG.finditer(text):
        check_shell_text(strip_quotes(bang.group(1)), context="a shell cell in %s" % label)


def scan_notebook(text, label):
    """Inspect a Jupyter notebook cell by cell: shell magics, `!` lines, then code."""
    try:
        notebook = json.loads(text)
        cells = notebook.get("cells") or []
    except Exception:
        scan_code_text(text, label)
        return
    for cell in cells:
        if not isinstance(cell, dict) or cell.get("cell_type") != "code":
            continue
        source = cell.get("source") or ""
        if isinstance(source, list):
            source = "".join(str(s) for s in source)
        lines = source.splitlines()
        if lines and CELL_SHELL_MAGIC.match(lines[0].strip()):
            scan_shell_lines(lines[1:], "a shell cell in %s" % label)
        for line in lines:
            stripped = line.lstrip()
            if stripped.startswith("!"):
                check_shell_text(stripped[1:], context="a shell line in %s" % label)
            elif re.match(r"%(?:sx|system|sc)\b", stripped):
                check_shell_text(stripped.split(None, 1)[-1], context="a shell line in %s" % label)
        scan_code_text(source, label)


def scan_script_file(path, label):
    suffix = path.suffix.lower()
    is_shell = suffix in SHELL_EXTENSIONS
    is_code = suffix in CODE_EXTENSIONS
    if not (is_shell or is_code):
        head = read_head(path)
        if head is None:
            return
        is_shell = looks_like_shell(path, head)
        is_code = looks_like_code(path, head)
        if not (is_shell or is_code):
            return
    text = read_script_text(path, label)
    if is_shell:
        scan_shell_lines(text.splitlines(), "the script %s" % label)
    elif suffix == ".ipynb":
        scan_notebook(text, label)
    else:
        scan_code_text(text, label)


def parse_makefile(text):
    """Return {target: (prerequisites, recipe_lines)} for a simple Makefile."""
    targets = {}
    current = None
    for line in text.splitlines():
        if line.startswith("\t"):
            if current is not None:
                targets[current][1].append(line[1:])
            continue
        m = re.match(r"^([A-Za-z0-9_./%\-]+)\s*:(?!=)\s*(.*)$", line)
        if m:
            current = m.group(1)
            prereqs = [p for p in m.group(2).split() if not p.startswith("#")]
            targets[current] = (prereqs, [])
        elif line.strip() == "" or not line[0].isspace():
            current = current if line.startswith(" ") else None
    return targets


def make_goals(words):
    """Parse `make [options] goal...` into (makefile, directory, goals)."""
    makefile = None
    directory = None
    goals = []
    i = 1
    while i < len(words):
        w = words[i]
        if w in ("-f", "--file", "--makefile") and i + 1 < len(words):
            makefile = words[i + 1]
            i += 2
            continue
        if w in ("-C", "--directory") and i + 1 < len(words):
            directory = words[i + 1]
            i += 2
            continue
        if w.startswith("-") or "=" in w:
            i += 1
            continue
        goals.append(w)
        i += 1
    return makefile, directory, goals


def scan_make(words, cwd):
    start = next((k for k, w in enumerate(words) if basename(w) in ("make", "gmake")), None)
    if start is None:
        return
    makefile, chdir, goals = make_goals(words[start:])
    directory = Path(cwd)
    if chdir:
        directory = Path(os.path.expanduser(chdir))
        if not directory.is_absolute():
            directory = Path(cwd) / directory
    candidates = [makefile] if makefile else ["GNUmakefile", "makefile", "Makefile"]
    text = None
    for name in candidates:
        p = Path(name)
        if not p.is_absolute():
            p = directory / p
        if p.is_file():
            text = read_script_text(p, str(p))
            break
    if not text:
        return
    text = text.replace("$(RM)", "rm -f").replace("${RM}", "rm -f")
    text = text.replace("$(MAKE)", "make").replace("${MAKE}", "make")
    targets = parse_makefile(text)
    if not targets:
        return
    if not goals:
        goals = [next(iter(targets))]
    seen = set()

    def visit(name, depth):
        if name in seen or depth > MAKE_MAX_DEPTH:
            return
        seen.add(name)
        entry = targets.get(name)
        if not entry:
            return
        prereqs, recipe = entry
        # Recipe prefixes (@ silence, - ignore errors, + always run) are not
        # part of the program name.
        lines = [re.sub(r"^\s*[@+-]+\s*", "", line) for line in recipe]
        scan_shell_lines(lines, "the Makefile target `%s`" % name)
        for line in lines:
            if re.match(r"\s*make\b", line):
                _, _, nested = make_goals(line.split())
                for goal in nested:
                    visit(goal, depth + 1)
        for p in prereqs:
            visit(p, depth + 1)

    for g in goals:
        visit(g, 0)
    if "clean" in goals or "distclean" in goals or "clobber" in goals:
        block("make clean", "Clean targets delete generated files. Ask the user to run this themselves.")


NPM_LIFECYCLE = {
    "test": ["pretest", "test", "posttest"],
    "start": ["prestart", "start", "poststart"],
    "stop": ["prestop", "stop", "poststop"],
    "restart": ["prerestart", "restart", "postrestart"],
}
NPM_INSTALL_SCRIPTS = ["preinstall", "install", "postinstall", "prepublish", "preprepare", "prepare", "postprepare"]
NPM_INSTALL_WORDS = {"install", "i", "ci", "add"}


def package_script_goals(words):
    """Which package.json scripts `npm run x` / `yarn x` / `pnpm x` would run."""
    tool = basename(words[0])
    args = [w for w in words[1:] if not w.startswith("-")]
    if "--" in words:
        args = [w for w in words[1:words.index("--")] if not w.startswith("-")]
    if not args:
        return []
    verb = args[0]
    if verb in ("run", "run-script"):
        return args[1:2]
    if verb in NPM_INSTALL_WORDS:
        return list(NPM_INSTALL_SCRIPTS)
    if verb in NPM_LIFECYCLE:
        return list(NPM_LIFECYCLE[verb])
    if tool in ("yarn", "pnpm", "bun") and verb not in ("exec", "dlx", "create", "x", "init", "why", "list", "ls", "info"):
        return [verb]
    return []


def scan_package_scripts(words, cwd):
    pkg = Path(cwd) / "package.json"
    if not pkg.is_file():
        return
    goals = package_script_goals(words)
    if not goals:
        return
    try:
        scripts = json.loads(read_script_text(pkg, "package.json")).get("scripts") or {}
    except Blocked:
        raise
    except Exception as exc:
        block("a package.json that cannot be inspected", "`%s` is not valid JSON (%s)." % (pkg, exc))
    if not isinstance(scripts, dict):
        return
    seen = set()

    def visit(name, depth):
        if name in seen or depth > MAKE_MAX_DEPTH:
            return
        seen.add(name)
        for key in ("pre" + name, name, "post" + name):
            script = scripts.get(key)
            if not isinstance(script, str):
                continue
            check_shell_text(script, context="the npm script `%s`" % key)
            for m in re.finditer(r"\b(?:npm|yarn|pnpm|bun)\s+(?:run(?:-script)?\s+)?([\w:.-]+)", script):
                visit(m.group(1), depth + 1)

    for goal in goals:
        visit(goal, 0)


def scan_referenced_scripts(command, cwd):
    firsts = list(command_position_tokens(defang(command)))
    if firsts and all(f in READ_ONLY_FIRST for f in firsts):
        return
    home = Path(os.path.expanduser("~"))
    base = Path(cwd)
    seen = set()
    for segment in SEGMENT_SPLIT.split(strip_quotes(command)):
        words = segment.split()
        if not words:
            continue
        # A `cd` moves the base directory for everything that follows it.
        j = 0
        while j < len(words) and ASSIGNMENT.match(words[j]):
            j += 1
        if j < len(words) and basename(words[j]) == "cd":
            dest = words[j + 1] if j + 1 < len(words) and not words[j + 1].startswith("-") else ""
            if not dest or dest == "~":
                base = home
            elif dest != "-":
                p = Path(os.path.expanduser(dest))
                base = p if p.is_absolute() else base / p
            continue
        prog = first_program(segment)
        if prog in ("make", "gmake"):
            scan_make(words, str(base))
        if prog in ("npm", "yarn", "pnpm", "bun"):
            scan_package_scripts(words[words.index(next(w for w in words if basename(w) == prog)):], str(base))
        for raw in PATH_TOKEN_SPLIT.split(segment):
            tok = raw.strip()
            if not tok or tok.startswith("-") or len(tok) > 400:
                continue
            for root in (base, Path(cwd)):
                candidate = Path(os.path.expanduser(tok))
                if not candidate.is_absolute():
                    candidate = root / candidate
                try:
                    if not candidate.is_file():
                        continue
                    resolved = candidate.resolve()
                except Exception:
                    continue
                if resolved not in seen:
                    seen.add(resolved)
                    scan_script_file(resolved, tok)
                break


# ---------------------------------------------------------------------------
# Redirect and move targets
# ---------------------------------------------------------------------------
SAFE_TARGETS = re.compile(r"^(/dev/null|/dev/stdout|/dev/stderr|/dev/tty)$")
TEMP_PREFIXES = ("/tmp", "/private/tmp", "/var/folders", "/private/var/folders")


def inside(path, root):
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def is_temp(path):
    text = str(path)
    return any(text == p or text.startswith(p + "/") for p in TEMP_PREFIXES)


def check_write_targets(command, project_root):
    root = Path(project_root).resolve()
    for m in WRITE_TARGET.finditer(command):
        target = m.group(1).strip("'\"")
        if not target or SAFE_TARGETS.match(target) or target.startswith("$"):
            continue
        if target.startswith("~") or target.startswith("/"):
            resolved = Path(os.path.expanduser(target)).resolve()
            if not inside(resolved, root) and not is_temp(resolved):
                block(
                    "writing a file outside the project folder",
                    "The command writes to `%s`, which is outside `%s`." % (target, root),
                )
    for m in re.finditer(r"(?:^|[;&|]\s*)\s*mv\s+(.+?)(?=$|[;&|])", defang(command)):
        args = [a for a in m.group(1).split() if not a.startswith("-")]
        if args:
            dest = args[-1]
            if dest.startswith("~") or dest.startswith("/"):
                resolved = Path(os.path.expanduser(dest)).resolve()
                if not inside(resolved, root):
                    block(
                        "moving files out of the project folder",
                        "`mv` to `%s` would take files out of `%s`. Use `cp` to copy instead."
                        % (dest, root),
                    )


# ---------------------------------------------------------------------------
# Bash entry point
# ---------------------------------------------------------------------------
def check_command(command, cwd, project_root):
    """Raise Blocked if the command must not run; return normally to allow it."""
    if not command.strip():
        return

    # 1. Shell-level checks on the command as written.
    check_shell_text(command)
    check_backup_dir(command)

    # 2. Inline scripts, scripts fed on stdin, and substitutions hide the real
    #    command inside quotes. Look at the hidden text as well.
    context = "an inline script or substitution"
    if INLINE_INTERP.search(command) or STDIN_SCRIPT.search(command):
        hidden = strip_quotes(command)
    elif SUBSTITUTION.search(command):
        hidden = substitution_bodies(command)
    else:
        hidden = ""
    if hidden.strip():
        check_banned(hidden, context=context)
        check_rules(PATTERN_RULES, hidden, context=context)
        check_download_pipelines(hidden, context=context)
        if SCRIPT_DELETE.search(hidden) or SCRIPT_SPAWN.search(hidden):
            block(
                "an inline script that deletes files or launches programs",
                "Inline interpreter scripts may not remove files or launch other programs. "
                "Put the code in a file and run it instead, so it can be inspected.",
            )

    # 3. A file written and executed in the same command cannot be inspected.
    check_write_then_run(command)

    # 4. Scripts on disk that this command would run.
    scan_referenced_scripts(command, cwd)

    # 5. Output written outside the project.
    check_write_targets(command, project_root)


# ---------------------------------------------------------------------------
# File-tool rules (Edit / Write / NotebookEdit / MultiEdit)
# ---------------------------------------------------------------------------
PROTECTED_FILE_PATTERNS = [
    (re.compile(r"/\.(zshrc|zprofile|zshenv|zlogin|zlogout|bashrc|bash_profile|bash_login|bash_logout|profile|envrc)$"),
     "a shell startup file"),
    (re.compile(r"/\.ssh(/|$)"), "the SSH key folder"),
    (re.compile(r"/\.aws(/|$)"), "the AWS credentials folder"),
    (re.compile(r"/\.gnupg(/|$)"), "the GnuPG key folder"),
    (re.compile(r"/\.(kube|config/gcloud)(/|$)"), "a cloud credentials folder"),
    (re.compile(r"/\.(netrc|pypirc|npmrc)$|/\.docker/config\.json$"), "a credentials file"),
    (re.compile(r"/Library/Keychains(/|$)"), "the macOS Keychain"),
    (re.compile(r"/Library/(LaunchAgents|LaunchDaemons|StartupItems)(/|$)"), "an autostart folder"),
    (re.compile(r"/Library/(Preferences|Application Support|Cookies|Safari|Mail|Messages|Accounts|Group Containers)(/|$)"),
     "a folder that holds application data and settings"),
    (re.compile(r"/Library/Python(/|$)|/site-packages(/|$)|/\.ipython(/|$)"),
     "a Python startup directory, which runs code every time Python starts"),
    (re.compile(r"/\.claude/settings(\.local)?\.json$"), "Claude Code's settings"),
    (re.compile(r"/\.claude\.json$|/\.mcp\.json$"), "Claude Code's configuration"),
    (re.compile(r"/\.claude/(hooks|agents|skills|commands|plugins|workflows)(/|$)|/\.claude/scheduled_tasks\.json$"),
     "a folder Claude Code loads and runs code from"),
    (re.compile(r"/ClaudeCode/|managed-settings|/claude-guard(/|$)|\.claude-safe-backups"), "the Claude Safe Mode configuration"),
    (re.compile(r"/\.git(/|$)"), "git's internal folder"),
    (re.compile(r"/\.(vscode|idea)(/|$)"), "editor configuration, which can point the editor at programs to run"),
    (re.compile(r"/\.?latexmkrc$"), "a latexmk configuration file, which can run arbitrary code"),
    (re.compile(r"/\.?Rprofile$|/\.Renviron$"), "an R startup file"),
    (re.compile(r"/(\.gitconfig|\.gitmodules)$"), "git's configuration"),
    (re.compile(r"/(Makefile|GNUmakefile|makefile)$"), "a Makefile, which runs shell commands"),
    (re.compile(r"/\.pre-commit-config\.yaml$|/lefthook\.ya?ml$|/\.husky/"), "a git hook manager configuration"),
]
# Checked separately so that the per-user temp directory (/var/folders/... on
# macOS, which sits under /private/var) stays writable for scratch files.
SYSTEM_FOLDER = re.compile(r"^/(System|usr|bin|sbin|etc|private/etc|private/var|Library|Applications|opt)(/|$)")


def check_file_tool(tool_input, cwd):
    """Raise Blocked for a protected path; otherwise snapshot the file and
    return a warning string if the backup failed, else None."""
    raw_path = None
    for key in ("file_path", "notebook_path", "path"):
        value = tool_input.get(key)
        if isinstance(value, str) and value:
            raw_path = value
            break
    if raw_path is None:
        return None

    candidate = Path(os.path.expanduser(raw_path))
    if not candidate.is_absolute():
        candidate = Path(cwd) / candidate
    resolved = candidate.resolve()
    as_text = str(resolved)
    if SYSTEM_FOLDER.search(as_text) and not is_temp(resolved):
        block("writing to a system folder", "`%s` is protected on this machine." % as_text)
    for rx, what in PROTECTED_FILE_PATTERNS:
        if rx.search(as_text):
            block("writing to %s" % what, "`%s` is protected on this machine." % as_text)

    return snapshot(resolved)


# ---------------------------------------------------------------------------
# Backups
# ---------------------------------------------------------------------------
def snapshot(path):
    """Copy the file about to be edited into the backup folder.

    Returns None on success (or when there is nothing to back up), or a
    warning string. A backup problem must never block legitimate work, but it
    must also never be silent, so the caller shows the warning to the user."""
    try:
        if not path.is_file() or path.stat().st_size > BACKUP_MAX_BYTES:
            return None
        now = datetime.now()
        day_dir = BACKUP_ROOT / now.strftime("%Y-%m-%d")
        flat = str(path).lstrip("/").replace("/", "__")
        day_dir.mkdir(parents=True, exist_ok=True)
        if not already_backed_up(path, day_dir, flat):
            shutil.copy2(str(path), str(unique_snapshot_name(day_dir, now, flat)))
        prune_backups()
        return None
    except Exception as exc:
        return report_backup_failure(path, exc)


def already_backed_up(path, day_dir, flat):
    """True if a snapshot of this file taken today has identical contents."""
    suffix = "__" + flat
    return any(filecmp.cmp(str(path), str(p), shallow=False)
               for p in day_dir.iterdir() if p.name.endswith(suffix))


def unique_snapshot_name(day_dir, now, flat):
    """Two different versions saved within one second must not overwrite each other."""
    stamp = now.strftime("%H-%M-%S")
    dest = day_dir / ("%s__%s" % (stamp, flat))
    n = 1
    while dest.exists():
        dest = day_dir / ("%s-%d__%s" % (stamp, n, flat))
        n += 1
    return dest


def report_backup_failure(path, exc):
    message = "Claude Safe Mode could not back up `%s` before editing it (%s). The edit was allowed." % (path, exc)
    try:
        BACKUP_ROOT.mkdir(parents=True, exist_ok=True)
        with open(str(BACKUP_ROOT / BACKUP_ERROR_FILE), "a") as fh:
            fh.write("%s %s\n" % (datetime.now().isoformat(timespec="seconds"), message))
    except Exception:
        pass  # the warning still reaches the user through the hook output
    return message


def prune_backups():
    cutoff = datetime.now() - timedelta(days=BACKUP_KEEP_DAYS)
    for child in BACKUP_ROOT.iterdir():
        if not child.is_dir():
            continue
        try:
            when = datetime.strptime(child.name, "%Y-%m-%d")
        except ValueError:
            continue
        if when < cutoff:
            shutil.rmtree(str(child), ignore_errors=True)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    """Return a list of messages for the user; raise Blocked to refuse the call."""
    raw = sys.stdin.buffer.read().decode("utf-8", "replace")
    if not raw.strip():
        block("the safety check received no tool call",
              "Refusing to run something that cannot be inspected.")
    try:
        payload = json.loads(raw)
    except Exception:
        block("the safety check could not read the tool call",
              "Refusing to run something that cannot be inspected.")
    if not isinstance(payload, dict):
        block("the safety check could not read the tool call",
              "Refusing to run something that cannot be inspected.")

    tool_name = payload.get("tool_name") or ""
    tool_input = payload.get("tool_input")
    cwd = payload.get("cwd") or os.getcwd()
    project_root = os.environ.get("CLAUDE_PROJECT_DIR") or cwd
    messages = []

    if tool_name not in BASH_TOOLS and tool_name not in FILE_TOOLS:
        return messages  # a tool the guard does not judge (Read, Glob, ...)
    if not isinstance(tool_input, dict):
        block("an unreadable tool call", "The tool input was not an object.")

    if tool_name in BASH_TOOLS:
        if tool_input.get("dangerouslyDisableSandbox"):
            block("a request to run outside the sandbox",
                  "Commands must stay inside the sandbox on this machine.")
        command = tool_input.get("command") or tool_input.get("script") or ""
        if not isinstance(command, str):
            block("an unreadable command", "The command was not plain text.")
        check_command(command, cwd, project_root)
    else:
        warning = check_file_tool(tool_input, cwd)
        if warning:
            messages.append(warning)
    return messages


if __name__ == "__main__":
    try:
        system_messages = main()
    except Blocked as blocked:
        sys.stderr.write(blocked.message())
        sys.exit(2)
    except SystemExit:
        raise
    except BaseException:
        sys.stderr.write(
            "Blocked by Claude Safe Mode: the safety check itself failed, so the "
            "tool call was refused.\n\n" + traceback.format_exc()
        )
        sys.exit(2)
    if system_messages:
        sys.stdout.write(json.dumps({"systemMessage": " ".join(system_messages)}) + "\n")
    sys.exit(0)
