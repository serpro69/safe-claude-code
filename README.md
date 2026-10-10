# Claude Safe Mode for macOS

A locked-down Claude Code configuration aimed at improving security
and confidence of running claude-code for non-technical users.

It is primarily built for non-tech-savvy researchers who want Claude Code in the
VS Code extension or the cli running on their mac (on Linux the files have to be
installed by hand, see below), but who is worried about claude running commands
they don't understand.

The goal: **ordinary work keeps working, and anything destructive is refused
before it runs.** The user is never relied on to read a command and
judge whether it is safe.

---

## What it protects against

Four independent layers, so a gap in one is covered by another. The VS Code
extension runs the same CLI underneath, so all four apply there too.

1. **The macOS sandbox (Seatbelt).** Shell commands can only write inside the
   project folder and the temp directory, and can only reach the network
   through a proxy that allows a fixed list of research websites (PyPI, CRAN,
   GitHub, arXiv, Hugging Face, and so on). Everything else is blocked by the
   operating system, even if Claude is talked into trying it.

2. **Deny rules in managed settings.** A long list of destructive commands and
   file edits is refused outright: `rm`, `sudo`, `dd`, `diskutil`, `chmod -R`,
   `git reset --hard`, `git push --force`, global package installs, writes to
   `~/.ssh`, shell startup files, and the Claude configuration itself. Deny
   rules beat every "allow" and every "don't ask again", from every source.

3. **A fail-closed guard script.** Before every command and every file edit, a
   Python script reads the _full_ command text and blocks dangerous forms that
   permission rules miss on their own: `/bin/rm`, `'rm'`, `sh -c 'rm -rf ~'`,
   `curl ... | /bin/sh`, `bash -c "$(curl ...)"`, a Python program fed on
   stdin with a heredoc, deletion calls hidden inside a Python or shell script
   on disk (also after a `cd`), a `make` target or `npm run` script that runs
   `rm`, a notebook shell cell, a script written and run in the same command,
   and so on. If the guard cannot run, cannot read the tool call, or cannot
   inspect a script, the command is **blocked**, never allowed. The guard runs
   under `python3 -I`, so nothing in the user's own Python setup is loaded
   into it.

4. **Automatic backups.** Every file Claude is about to change is copied into
   `~/.claude-safe-backups/` first, so any unwanted edit can be recovered. Kept
   for 30 days; unchanged files are not copied twice. If a backup ever fails,
   the edit still goes ahead but the user sees a warning and `verify.sh`
   reports it.

The configuration lives in the root-owned managed-settings location, so a
Claude session **cannot turn off its own guardrails** — it would need the
admin password, which Claude never has. `bypassPermissions` mode and the
"run outside the sandbox" escape hatch are both disabled.

---

## What still works

Normal research work is untouched:

- running scripts: `python3 analysis.py`, `Rscript model.R`, `jupyter`, `pytest`
- building documents: `pdflatex`, `latexmk`, `pandoc`
- reading and editing project files, notebooks, and data
- `git status`, `git add`, `git commit`, `git pull`, `git fetch`
- downloading papers and datasets from the allowed research sites
- creating folders and output files inside the project

A few medium-risk actions **ask first** instead of being blocked, so they are
possible but never silent: `pip install`, `npm install`, `conda install`,
`git push` (plain), and `mv`.

---

## Requirements

- **Claude Code 2.1.295 or newer**, as the CLI or the VS Code extension. Older
  versions let a tool call through when a hook fails to start, which would
  silently remove the guard layer; `install.sh` and `verify.sh` warn if they
  find an older `claude`. Check with `claude --version`.
- **macOS** with the Command Line Tools installed (`xcode-select --install`),
  so that `/usr/bin/python3` works. Linux needs a manual install, see below.
- An **administrator account**: the installer needs `sudo` to write the
  root-owned policy and guard.

## Install

On a MacBook, in the terminal:

```bash
git clone https://github.com/serpro69/safe-claude-code.git ~/claude-safe-mode
cd ~/claude-safe-mode
sudo ./install.sh
```

The installer validates the policy, runs the guard's test suite, installs the
guard to `/usr/local/claude-guard/`, self-tests the installed copy (confirms it
blocks `rm -rf /` and allows `ls`), then writes the policy to
`/Library/Application Support/ClaudeCode/managed-settings.json` as root.

Then **fully quit and reopen VS Code** (or the `claude` CLI). The policy is read
at startup.

On Linux the installer refuses to run. Copy `managed-settings.json` to
`/etc/claude-code/managed-settings.json` and `hooks/guard.py` plus
`hooks/guard.sh` to `/usr/local/claude-guard/` as root, make them
world-readable, then run `./verify.sh`. The macOS-only parts of the policy
(the Seatbelt sandbox, `diskutil`, Keychain paths) are simply inert there.

## Verify

```bash
./verify.sh
```

This confirms the files are in place, owned by root, and that the guard blocks
destructive commands while allowing research commands. You can also run
`claude doctor`, or `/status` inside a session, to confirm Claude Code loaded
the managed settings.

## Uninstall

```bash
sudo ./uninstall.sh
```

Removes the policy and the guard. Your backups in `~/.claude-safe-backups` are
left alone.

---

## Files

| File                    | Purpose                                                                   |
| :---------------------- | :------------------------------------------------------------------------ |
| `managed-settings.json` | The policy: permission modes, deny/ask rules, sandbox, hook registration. |
| `hooks/guard.py`        | The guard. Inspects every command and file edit; fail-closed.             |
| `hooks/guard.sh`        | Wrapper that guarantees the guard fails closed even if Python is missing. |
| `install.sh`            | Installs and self-tests everything (needs `sudo`).                        |
| `verify.sh`             | Checks the install and runs live block/allow tests.                       |
| `uninstall.sh`          | Removes the policy and guard (needs `sudo`).                              |
| `tests/test_guard.py`   | 300+ tests for the guard and wrapper. Run `python3 tests/test_guard.py`.  |
| `USERGUIDE.md`          | Plain-language user guide.                                                |

---

## Tuning it

Everything is meant to be adjusted. After any change, re-run
`sudo ./install.sh` and restart Claude Code.

- **Allow another website** (for example a journal or data repository the user
  needs): add the domain to `sandbox.network.allowedDomains` in
  `managed-settings.json`.
- **Allow a command that is being blocked too aggressively**: the guard prints
  exactly why it blocked. If it is a false positive, loosen or remove the
  matching rule in `hooks/guard.py` (`PATTERN_RULES`) or the deny list. Two
  deliberate strict spots: `$(curl ...)` is refused even when it only captures
  output (use `curl -o file` instead), and a single quoted word such as
  `'rm'` is treated as a program name, not prose.
- **Block something else**: add a `deny` rule in `managed-settings.json` and a
  matching rule in `guard.py`.
- **Turn a hard block into an "ask first"**: move the entry from `deny` to `ask`
  in `managed-settings.json`. Note the guard still blocks the most destructive
  commands regardless; relax the guard too if you want it to only prompt.
- **Fewer prompts on file edits.** The installed baseline is Manual mode
  (`permissions.defaultMode: "default"`), so Claude asks before each file edit.
  If that is too many prompts, change it to `"acceptEdits"`: Claude then edits
  project files without asking, while the deny rules, the guard, the sandbox,
  and the automatic backups all still apply. The user can also switch mode
  mid-session with Shift+Tab; the two unsafe modes (`bypassPermissions` and
  `auto`) are disabled and cannot be selected.

---

## Known limits (be honest about these)

- **It is not a malware sandbox.** The macOS sandbox restricts files and
  network for shell commands, but the docs note that a broadly-allowed domain
  could in theory be used for data exfiltration, and some tools need to run
  outside the sandbox. This setup is about preventing accidental destruction and
  obvious foot-guns, not defeating a determined attacker.
- **The guard inspects command text and referenced scripts, not every possible
  path.** A program that reads a file path from stdin at runtime, an
  already-compiled binary, a Python module run with `-m`, a `conftest.py`
  pulled in by `pytest`, or a Makefile `include` is not inspected. The sandbox
  and deny rules are the backstop for those.
- **The script scanner looks for deletion calls, not every way to lose data.**
  `shutil.move`, `os.rename` and `open(path, "w")` inside a script are not
  treated as deletion, because they are reversible or far too common. A script
  larger than 64 MB is refused rather than inspected.
- **Staging across separate tool calls is caught; the written file is on disk
  by the time it runs. Staging inside one command (`echo ... > s.sh && bash
  s.sh`) is refused outright** rather than inspected, because the file does
  not exist yet when the guard looks.
- **Downloaded code still runs** if the user asks Claude to run a script it just
  downloaded from an allowed site, as long as that script contains nothing on
  the block list. Review matters for anything genuinely untrusted.
- **A plain `git push` is allowed after a prompt.** Force-push and branch
  deletion are blocked, but a normal push to the user's own repository is a
  routine, reversible action, so it only asks.
- **Project MCP servers are blocked outright.** A repository's `.mcp.json`
  would otherwise start a process with the user's full access after one
  prompt. Servers delivered through managed settings still work.

For stronger isolation (a full container or VM), see Claude Code's
`sandbox-environments` and `devcontainer` documentation.

---

## TODO

- [ ] Upgrade procedure for when this repo introduces new changes
