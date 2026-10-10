# Using Claude Code safely — a short guide

Your computer has been set up with **Claude Safe Mode**. You can let Claude
Code work on your files in VS Code without worrying that it will run something
that damages your machine or deletes your work.

You do not need to understand the commands Claude runs. The safety net does
that for you.

## What this means day to day

- **You can let Claude run commands.** Dangerous ones are refused automatically
  before they do anything.
- **Your files are backed up.** Every time Claude changes a file, a copy of the
  old version is saved first, in a hidden folder called `.claude-safe-backups`
  in your home folder. If Claude ever changes something you didn't want, the
  previous version is there. If a backup ever fails, Claude shows you a
  warning saying so.
- **Your passwords and keys are off limits.** Claude cannot read your saved
  passwords, SSH keys, or browser data.
- **The internet is limited** to research sites (where Python packages, R
  packages, papers, and datasets come from).

## When Claude says it was "blocked by Claude Safe Mode"

This is normal and expected. It means Claude tried to do something on the
block list and the safety net stopped it. Claude will explain what it wanted to
do. You have two choices:

1. **Usually: just carry on.** Ask Claude to do the task a different, safe way.
   Most of the time it can.
2. **If you really need that exact action** (say, deleting a folder, or
   installing a system tool), _ask Claude how to do it, then do it yourself_
   in a normal Terminal window. The block is there on purpose.

## When Claude asks "Do you want to proceed?"

A few actions are not blocked but will **ask you first**: installing a Python or
R package, pushing your work to GitHub, or moving files. If you were expecting
it, choose yes. If it surprises you, choose no and ask Claude what it is for.

## A few habits that help

- **Work inside a project folder.** Keep each piece of work in its own folder
  and open that folder in VS Code. Claude can freely read and edit files there,
  and the safety net keeps it from wandering outside.
- **Use git if you can.** Even basic git (committing your work regularly) means
  there is always a saved version to go back to. Claude can help you set this
  up and do the day-to-day operations with git.
- **If something looks wrong, stop and ask.** You can always close the window.
  Nothing Claude does is instant and irreversible under this setup.

## If you ever need to recover a file

The backups are in your home folder, in `.claude-safe-backups`, sorted by date.
Ask Claude: *"show me the backups of this file from today"* and it can find the
earlier version for you to restore.

That's it. Work normally, and let the safety net do its job.
