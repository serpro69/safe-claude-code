# Claude Safe Mode for macOS

A locked-down Claude Code configuration for a non-technical user.

It is built for non-tech-savvy people (for example, someone doing a
non-technical PhD research on their mac (linux is partially supported,
but some features will be unavailable) who wants Claude Code in the VS Code
extension or the cli, but is worried about it running commands they don't understand.

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
   permission rules miss on their own: `/bin/rm`, `sh -c 'rm -rf ~'`,
   `curl ... | bash`, deletion calls hidden inside a Python or shell script on
   disk, a `make` target that runs `rm`, and so on. If the guard cannot run for
   any reason, the command is **blocked**, never allowed.

4. **Automatic backups.** Every file Claude is about to change is copied into
   `~/.claude-safe-backups/` first, so any unwanted edit can be recovered. Kept
   for 30 days.

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

## Install

On a MacBook, in the terminal:

```bash
git clone https://github.com/serpro69/safe-claude-code.git ~/claude-safe-mode
cd ~/claude-safe-mode
sudo ./install.sh
```

The installer validates the policy, installs the guard to
`/usr/local/claude-guard/`, self-tests it (confirms it blocks `rm -rf /` and
allows `ls`), then writes the policy to
`/Library/Application Support/ClaudeCode/managed-settings.json` as root.

Then **fully quit and reopen VS Code** (or the `claude` CLI). The policy is read
at startup.

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
| `tests/test_guard.py`   | 160+ unit tests for the guard. Run `python3 tests/test_guard.py`.         |
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
  matching rule in `hooks/guard.py` (`PATTERN_RULES`) or the deny list.
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
  path.** A program that reads a file path from stdin at runtime, or an
  already-compiled binary, is not inspected. The sandbox and deny rules are the
  backstop for those.
- **Downloaded code still runs** if the user asks Claude to run a script it just
  downloaded from an allowed site, as long as that script contains nothing on
  the block list. Review matters for anything genuinely untrusted.
- **A plain `git push` is allowed after a prompt.** Force-push and branch
  deletion are blocked, but a normal push to the user's own repository is a
  routine, reversible action, so it only asks.

For stronger isolation (a full container or VM), see Claude Code's
`sandbox-environments` and `devcontainer` documentation.

--

## TODO

- [ ] Upgrade procedure for when this repo introduces new changes
