#!/usr/bin/env python3
"""
Claude Safe Mode - PreToolUse guard.

Runs before every Bash / PowerShell / Monitor command and before every file
edit. It inspects the full text of the command, not just the first word, so it
also catches forms that permission rules miss: `/bin/rm`, `sh -c 'rm -rf ~'`,
`curl ... | bash`, `r'm'`, `python -c "shutil.rmtree(...)"`, and scripts on
disk that a command is about to execute.

Contract with Claude Code:
  exit 0  -> allow (the tool call continues through the normal permission flow)
  exit 2  -> BLOCK the tool call; stderr is shown to Claude as the reason

The script is fail-closed: any unexpected error blocks the tool call.

It also snapshots every file Claude is about to modify into
~/.claude-safe-backups/ so an unwanted edit can always be recovered.
"""

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
SCRIPT_SCAN_MAX_BYTES = 2 * 1024 * 1024


# ---------------------------------------------------------------------------
# Exit helpers
# ---------------------------------------------------------------------------
def block(title: str, detail: str = "") -> NoReturn:
    lines = ["Blocked by Claude Safe Mode: " + title]
    if detail:
        lines += ["", detail]
    lines += [
        "",
        "This computer is configured to refuse destructive operations. Do not "
        "retry the same thing in a different form. Explain to the user what you "
        "wanted to do and why, and let them do it themselves if they decide it "
        "is safe.",
    ]
    sys.stderr.write("\n".join(lines) + "\n")
    sys.exit(2)


def allow() -> NoReturn:
    sys.exit(0)


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

# ---------------------------------------------------------------------------
# Pattern rules: (regex, title, explanation).
#
# PATTERN_RULES run on the command with quoted prose removed, so a commit
# message that mentions "clean up" does not trip the `git clean` rule.
# PATH_RULES run on the command with quote characters stripped, so a quoted
# path such as "~/Library/Application Support/..." is still seen.
# ---------------------------------------------------------------------------
def _r(pattern: str):
    return re.compile(pattern, re.IGNORECASE)


GIT = r"\bgit\s+(?:-[^\s]+\s+)*"   # `git`, optional global flags, then the subcommand

PATTERN_RULES = [
    # downloading and executing code
    (_r(r"\b(curl|wget|fetch)\b[^|&;]*\|\s*(sudo\s+)?(ba|z|k|da|a)?sh\b"),
     "piping a download straight into a shell",
     "`curl ... | sh` runs code from the internet without anyone reading it first."),
    (_r(r"\b(curl|wget|fetch)\b[^|&;]*\|\s*(sudo\s+)?(python3?|perl|ruby|node|osascript)\b"),
     "piping a download straight into an interpreter",
     "This runs code from the internet without anyone reading it first."),
    (_r(r"<\s*\(\s*(curl|wget|fetch)\b"),
     "executing a download through process substitution",
     "`bash <(curl ...)` runs code from the internet without anyone reading it first."),
    (_r(r"\beval\b"),
     "eval",
     "`eval` runs generated text as code."),
    (_r(r"\bbase64\b[^|&;]*(-d|-D|--decode)[^|&;]*\|\s*(ba|z|)sh\b"),
     "decoding and executing obfuscated code",
     "Decoding base64 straight into a shell hides what is being run."),

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
    (_r(GIT + r"restore\b"),
     "git restore",
     "This throws away uncommitted edits."),
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
    (_r(GIT + r"config\b(?![^\n]*(--get\b|--get-all\b|--get-regexp\b|--list\b|\s-l\b))"),
     "changing git configuration",
     "Git configuration can run hooks and aliases. Only read-only `git config --get` is allowed."),
    (_r(r"\bgit\s+(?:-[^\s]+\s+)*-c\s"),
     "git with an inline config override",
     "`git -c` can point git at a script to run."),
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

PATH_RULES = [
    (_r(r"LaunchAgents|LaunchDaemons|StartupItems|/etc/periodic"), "touching an autostart folder",
     "Files in these folders run every time the machine starts."),
    (_r(r"(>>?|\btee\b|\bcp\b|\bmv\b|\bln\b|\binstall\b)[^\n]*\.(zshrc|zprofile|zshenv|zlogin|zlogout|bashrc|bash_profile|bash_login|bash_logout|profile|envrc)\b"),
     "writing to a shell startup file",
     "Code in a shell startup file runs every time a terminal opens."),
    (_r(r"(^|[\s=:~/])\.(ssh|aws|gnupg|docker|kube|config/gcloud)(/|\s|$)|(^|[\s=:~/])\.(netrc|pypirc)\b"),
     "touching credential files", "These files hold keys and passwords."),
    (_r(r"\bid_(rsa|dsa|ecdsa|ed25519)\b"), "touching an SSH private key", "This is a private key."),
    (_r(r"Keychains?/|\blogin\.keychain|\bkeychain-db\b"), "touching the macOS Keychain",
     "The Keychain holds your saved passwords."),
    (_r(r"\bdefaults\b[^\n]*\s(write|delete|import|rename)\b"), "changing application preferences",
     "This rewrites the preferences of applications on the machine."),
    (_r(r"\bxattr\b[^\n]*(\s-[a-zA-Z]*[cd]\b|--clear|--delete)"), "removing file attributes",
     "This strips quarantine and other protective attributes."),
    (_r(r"managed-settings|/claude-guard(/|$)|com\.anthropic\.claudecode|/ClaudeCode/|\.claude-safe-backups"),
     "touching the Claude Safe Mode configuration", "The safety rules themselves are off limits."),
    (_r(r"\.claude/settings|\.claude\.json\b|\.mcp\.json\b|\.claude/hooks|\.claude/plugins|\.claude/agents|\.claude/skills|\.claude/commands"),
     "touching Claude Code's own settings", "Changing these files could switch the safety rules off."),
    (_r(r"/dev/(r?disk|sd[a-z]|nvme)"), "touching a raw disk device",
     "Writing to a raw disk device destroys the drive's contents."),
    (_r(r"\.git/(hooks|config)\b"), "touching git hooks or config",
     "Git hooks run arbitrary code on every commit."),
    (_r(r"\.?latexmkrc\b|\.Rprofile\b|\.Renviron\b"), "touching a tool startup file",
     "These files run code every time the tool starts."),
]

# ---------------------------------------------------------------------------
# Inline-script detection
# ---------------------------------------------------------------------------
INLINE_SHELL = re.compile(
    r"\b(?:ba|z|k|da|a)?sh\s+(?:-[A-Za-z]+\s+)*-c\b"
    r"|\b(?:python3?|pythonw|perl|ruby|node|deno|bun|osascript|Rscript)\s+(?:-[A-Za-z]+\s+)*-(?:c|e|E)\b"
    r"|\bR\s+(?:-[A-Za-z]+\s+)*-e\b"
    r"|\bxargs\b|\bsource\b|(^|[\s;&|])\.\s+\S|\$\(|`|<\(|>\(",
    re.IGNORECASE,
)

# Function-level danger inside Python, R, JavaScript, Julia, SQL and notebooks.
SCRIPT_DELETE = re.compile(
    r"shutil\.rmtree|os\.remove\b|os\.unlink\b|os\.rmdir\b|os\.removedirs\b|os\.truncate\b"
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

SHELL_EXTENSIONS = {".sh", ".bash", ".zsh", ".ksh", ".command"}
CODE_EXTENSIONS = {
    ".py", ".pyw", ".ipynb", ".r", ".rmd", ".qmd", ".jl", ".js", ".mjs", ".cjs",
    ".ts", ".rb", ".pl", ".pm", ".php", ".lua", ".scpt", ".applescript", ".sql",
}
READ_ONLY_FIRST = {
    "cat", "head", "tail", "less", "more", "grep", "rg", "egrep", "fgrep", "wc",
    "diff", "ls", "stat", "file", "md5", "md5sum", "shasum", "sha256sum", "git",
    "find", "cp", "sort", "uniq", "cut", "awk", "tr", "echo", "printf", "test",
    "mkdir", "touch", "cd", "pwd", "which", "type", "code", "open", "du", "df",
    "tree", "bat", "pandoc", "pdflatex", "xelatex", "lualatex", "latexmk",
    "bibtex", "biber", "jq", "yq", "column", "paste", "join", "comm", "nl",
    "strings", "hexdump", "xxd", "od", "basename", "dirname", "realpath",
    "readlink", "date", "cal", "env", "printenv", "true", "false", "sleep",
    "ln", "mv", "tar", "zip", "unzip", "pip", "pip3", "pipx", "black", "ruff",
    "flake8", "mypy", "pytest", "texcount", "detex", "chktex", "lacheck",
}


# ---------------------------------------------------------------------------
# Tokenising helpers
# ---------------------------------------------------------------------------
QUOTED = re.compile(r"'[^']*'|\"(?:[^\"\\]|\\.)*\"")
SEGMENT_SPLIT = re.compile(r"\|\||&&|[|;&\n(){}]")
TOKEN_SPLIT = re.compile(r"[\s;&|()<>{},=\n]+")


def defang(text: str) -> str:
    """
    Remove quoted prose, but keep quoted text that is glued to a word.

    `git commit -m "clean up"`  ->  `git commit -m  Q `
    `r'm' -rf x`                ->  `rm -rf x`
    """
    text = text.replace("\\", "")
    out = []
    i = 0
    for m in QUOTED.finditer(text):
        before = text[m.start() - 1] if m.start() > 0 else " "
        after = text[m.end()] if m.end() < len(text) else " "
        glued = (not before.isspace()) or (not after.isspace())
        out.append(text[i:m.start()])
        out.append(m.group(0)[1:-1] if glued else " Q ")
        i = m.end()
    out.append(text[i:])
    return "".join(out)


def strip_quotes(text: str) -> str:
    return re.sub(r"""['"\\]""", "", text).replace("`", " ")


def basename(token: str) -> str:
    tok = token.strip()
    if "/" in tok:
        tok = tok.rsplit("/", 1)[-1]
    return tok


def command_position_tokens(text: str):
    """Yield the basename of the program each simple command runs."""
    for segment in SEGMENT_SPLIT.split(text):
        words = segment.split()
        i = 0
        while i < len(words):
            w = words[i]
            if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", w):
                i += 1
                continue
            b = basename(w)
            if b in WRAPPERS and b not in ALL_BANNED:
                i += 1
                if b == "timeout" and i < len(words):
                    i += 1
                while i < len(words) and words[i].startswith("-"):
                    i += 1
                continue
            yield b
            break


def check_banned(text: str, context: str = "") -> None:
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


def check_rules(rules, text: str, context: str = "") -> None:
    for rx, title, detail in rules:
        if rx.search(text):
            if context:
                detail += "\n(Found in %s.)" % context
            block(title, detail)


def check_shell_text(text: str, context: str = "") -> None:
    """Run every shell-level check against a piece of shell text."""
    check_banned(defang(text), context)
    check_rules(PATTERN_RULES, defang(text), context)
    check_rules(PATH_RULES, strip_quotes(text), context)


# ---------------------------------------------------------------------------
# Script-file inspection
# ---------------------------------------------------------------------------
def looks_like_shell(path: Path, head: str) -> bool:
    if path.suffix.lower() in SHELL_EXTENSIONS:
        return True
    return bool(re.match(r"#!.*\b(ba|z|k|da|a)?sh\b", head))


def looks_like_code(path: Path, head: str) -> bool:
    if path.suffix.lower() in CODE_EXTENSIONS:
        return True
    return bool(re.match(r"#!.*\b(python|perl|ruby|node|Rscript|julia|osascript)", head))


def read_text(path: Path):
    try:
        if path.stat().st_size > SCRIPT_SCAN_MAX_BYTES:
            return None
        return path.read_text(errors="replace")
    except Exception:
        return None


def scan_shell_lines(lines, label: str) -> None:
    for line in lines:
        if line.lstrip().startswith("#!"):
            continue
        code = line.split("#", 1)[0]
        if code.strip():
            check_shell_text(code, context=label)


def scan_code_text(text: str, label: str) -> None:
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


def scan_script_file(path: Path, label: str) -> None:
    text = read_text(path)
    if text is None:
        return
    head = text[:200]
    if looks_like_shell(path, head):
        scan_shell_lines(text.splitlines(), "the script %s" % label)
    elif looks_like_code(path, head):
        scan_code_text(text, label)


def parse_makefile(text: str):
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


def scan_make(command: str, cwd: str) -> None:
    words = strip_quotes(command).split()
    makefile = None
    directory = Path(cwd)
    goals = []
    i = 1
    while i < len(words):
        w = words[i]
        if w in ("-f", "--file", "--makefile") and i + 1 < len(words):
            makefile = words[i + 1]
            i += 2
            continue
        if w in ("-C", "--directory") and i + 1 < len(words):
            directory = Path(os.path.expanduser(words[i + 1]))
            if not directory.is_absolute():
                directory = Path(cwd) / directory
            i += 2
            continue
        if w.startswith("-") or "=" in w:
            i += 1
            continue
        goals.append(w)
        i += 1
    candidates = [makefile] if makefile else ["GNUmakefile", "makefile", "Makefile"]
    text = None
    for name in candidates:
        p = Path(name)
        if not p.is_absolute():
            p = directory / p
        if p.is_file():
            text = read_text(p)
            break
    if not text:
        return
    text = text.replace("$(RM)", "rm -f").replace("${RM}", "rm -f")
    targets = parse_makefile(text)
    if not targets:
        return
    if not goals:
        goals = [next(iter(targets))]
    seen = set()

    def visit(name, depth):
        if name in seen or depth > 3:
            return
        seen.add(name)
        entry = targets.get(name)
        if not entry:
            return
        prereqs, recipe = entry
        scan_shell_lines(recipe, "the Makefile target `%s`" % name)
        for p in prereqs:
            visit(p, depth + 1)

    for g in goals:
        visit(g, 0)
    if "clean" in goals or "distclean" in goals or "clobber" in goals:
        block("make clean", "Clean targets delete generated files. Ask the user to run this themselves.")


def scan_referenced_scripts(command: str, cwd: str) -> None:
    firsts = list(command_position_tokens(defang(command)))
    if firsts and all(f in READ_ONLY_FIRST for f in firsts):
        return
    if firsts and firsts[0] in ("make", "gmake"):
        scan_make(command, cwd)
    seen = set()
    for raw in re.split(r"[\s;&|()<>]+", strip_quotes(command)):
        tok = raw.strip()
        if not tok or tok.startswith("-") or len(tok) > 400:
            continue
        candidate = Path(os.path.expanduser(tok))
        if not candidate.is_absolute():
            candidate = Path(cwd) / candidate
        try:
            if not candidate.is_file():
                continue
            resolved = candidate.resolve()
        except Exception:
            continue
        if resolved in seen:
            continue
        seen.add(resolved)
        scan_script_file(resolved, tok)


# ---------------------------------------------------------------------------
# Redirect and move targets
# ---------------------------------------------------------------------------
SAFE_TARGETS = re.compile(r"^(/dev/null|/dev/stdout|/dev/stderr|/dev/tty)$")
TEMP_PREFIXES = ("/tmp", "/private/tmp", "/var/folders", "/private/var/folders")


def inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def check_write_targets(command: str, project_root: str) -> None:
    root = Path(project_root).resolve()
    for m in re.finditer(r"(?<![<>])>{1,2}\s*([^\s;|&<>]+)", command):
        target = m.group(1).strip("'\"")
        if not target or SAFE_TARGETS.match(target) or target.startswith("$"):
            continue
        if target.startswith("~") or target.startswith("/"):
            resolved = Path(os.path.expanduser(target)).resolve()
            if not inside(resolved, root) and not str(resolved).startswith(TEMP_PREFIXES):
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
def check_command(command: str, cwd: str, project_root: str) -> NoReturn:
    if not command.strip():
        allow()

    # 1. Shell-level checks on the command as written.
    check_shell_text(command)

    # 2. Inline scripts and substitutions hide the real command inside
    #    quotes. Strip all quoting and look again.
    if INLINE_SHELL.search(command):
        unquoted = strip_quotes(command)
        check_banned(unquoted, context="an inline script or substitution")
        check_rules(PATTERN_RULES, unquoted, context="an inline script or substitution")
        if SCRIPT_DELETE.search(unquoted) or SCRIPT_SPAWN.search(unquoted):
            block(
                "an inline script that deletes files or launches programs",
                "Inline interpreter scripts may not remove files or launch other programs. "
                "Put the code in a file and run it instead, so it can be inspected.",
            )

    # 3. Scripts on disk that this command would run.
    scan_referenced_scripts(command, cwd)

    # 4. Output written outside the project.
    check_write_targets(command, project_root)

    allow()


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
    (re.compile(r"^/(System|usr|bin|sbin|etc|private/etc|private/var|Library|Applications|opt)(/|$)"),
     "a system folder"),
    (re.compile(r"/Library/(Preferences|Application Support|Cookies|Safari|Mail|Messages|Accounts|Group Containers)(/|$)"),
     "a folder that holds application data and settings"),
    (re.compile(r"/\.claude/settings(\.local)?\.json$"), "Claude Code's settings"),
    (re.compile(r"/\.claude\.json$|/\.mcp\.json$"), "Claude Code's configuration"),
    (re.compile(r"/\.claude/(hooks|agents|skills|commands|plugins|workflows)(/|$)|/\.claude/scheduled_tasks\.json$"),
     "a folder Claude Code loads and runs code from"),
    (re.compile(r"/ClaudeCode/|managed-settings|/claude-guard(/|$)|\.claude-safe-backups"), "the Claude Safe Mode configuration"),
    (re.compile(r"/\.git(/|$)"), "git's internal folder"),
    (re.compile(r"/\.(vscode|idea)/(tasks|launch)\.json$"), "editor task configuration that can run commands"),
    (re.compile(r"/\.?latexmkrc$"), "a latexmk configuration file, which can run arbitrary code"),
    (re.compile(r"/\.?Rprofile$|/\.Renviron$"), "an R startup file"),
    (re.compile(r"/(\.gitconfig|\.gitmodules)$"), "git's configuration"),
    (re.compile(r"/(Makefile|GNUmakefile|makefile)$"), "a Makefile, which runs shell commands"),
    (re.compile(r"/\.pre-commit-config\.yaml$|/lefthook\.ya?ml$|/\.husky/"), "a git hook manager configuration"),
]


def check_file_tool(tool_input: dict) -> NoReturn:
    raw_path = None
    for key in ("file_path", "notebook_path", "path"):
        value = tool_input.get(key)
        if isinstance(value, str) and value:
            raw_path = value
            break
    if raw_path is None:
        allow()

    resolved = Path(os.path.expanduser(raw_path)).resolve()
    as_text = str(resolved)
    for rx, what in PROTECTED_FILE_PATTERNS:
        if rx.search(as_text):
            block("writing to %s" % what, "`%s` is protected on this machine." % as_text)

    snapshot(resolved)
    allow()


# ---------------------------------------------------------------------------
# Backups
# ---------------------------------------------------------------------------
def snapshot(path: Path) -> None:
    try:
        if not path.is_file() or path.stat().st_size > BACKUP_MAX_BYTES:
            return
        now = datetime.now()
        day_dir = BACKUP_ROOT / now.strftime("%Y-%m-%d")
        flat = str(path).lstrip("/").replace("/", "__")
        dest = day_dir / ("%s__%s" % (now.strftime("%H-%M-%S"), flat))
        day_dir.mkdir(parents=True, exist_ok=True)
        if not dest.exists():
            shutil.copy2(str(path), str(dest))
        prune_backups()
    except Exception:
        pass  # a backup problem must never block legitimate work


def prune_backups() -> None:
    try:
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
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main() -> NoReturn:
    raw = sys.stdin.read()
    if not raw.strip():
        allow()
    try:
        payload = json.loads(raw)
    except Exception:
        block("the safety check could not read the tool call",
              "Refusing to run something that cannot be inspected.")
    if not isinstance(payload, dict):
        block("the safety check could not read the tool call",
              "Refusing to run something that cannot be inspected.")

    tool_name = payload.get("tool_name") or ""
    tool_input = payload.get("tool_input") or {}
    if not isinstance(tool_input, dict):
        tool_input = {}
    cwd = payload.get("cwd") or os.getcwd()
    project_root = os.environ.get("CLAUDE_PROJECT_DIR") or cwd

    if tool_name in ("Bash", "PowerShell", "Monitor"):
        if tool_input.get("dangerouslyDisableSandbox"):
            block("a request to run outside the sandbox",
                  "Commands must stay inside the sandbox on this machine.")
        command = tool_input.get("command") or tool_input.get("script") or ""
        if not isinstance(command, str):
            block("an unreadable command", "The command was not plain text.")
        check_command(command, cwd, project_root)
    elif tool_name in ("Edit", "Write", "NotebookEdit", "MultiEdit"):
        check_file_tool(tool_input)

    allow()


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception:
        sys.stderr.write(
            "Blocked by Claude Safe Mode: the safety check itself failed, so the "
            "tool call was refused.\n\n" + traceback.format_exc()
        )
        sys.exit(2)
