---
name: jj-vcs
description: Using jj (Jujutsu) for version control. Make sure to use this skill whenever the user mentions jj, jujutsu, version control, commits, branches/bookmarks, rebasing, history rewriting, cloning/pushing/pulling, or any VCS workflow — even when they don't explicitly say "jj." This skill covers daily editing, history restructuring, collaboration with remotes, and recovery from mistakes. When the user's repository uses jj (look for a .jj/ directory), ALWAYS use jj commands instead of git commands.
allowed-tools: Bash(jj:*)
license: MIT
metadata:
  author: OpticLM
  version: "0.41.0.2"
---

## Core mental model

jj is a Git-compatible version control system built around *changes* (revisions) that evolve over time. Each change has a **change ID** (stable — follows the change across rebases) and a **commit hash** (changes whenever the commit content changes). Refer to changes by their change ID (short prefix form) when you want to track a logical change, or by commit hash when pinning exact content.

Key differences from Git:
- **No staging area.** The working copy (`@`) is itself a commit. `jj status` compares `@` to its parent. Changes to tracked files are automatically part of `@`.
- **Change IDs**, not branch names, are the primary way history is organized. A commit's change ID survives rebase, squash, and split.
- **Operation log.** Every jj command creates an operation. `jj undo` simply undoes the last operation. `jj op log` shows the full history of commands run. Nothing is lost unless you explicitly garbage-collect.
- **Bookmarks, not branches.** Bookmarks are labels on revisions. To move a bookmark to point at a different revision, use `jj bookmark move`. Git branches are just bookmarks that jj syncs to the remote.
- **Revsets.** jj's revision selection language. Used everywhere commands accept revisions. Learn the common patterns (see core-concepts.md).

---

## Finding the right command

### Daily work loop

The core cycle is: **start a change → make edits → describe → (optionally) start the next change.**

| Intent | Command |
|---|---|
| See what's changed in `@` | `jj status` (aliases: `st`) |
| See file-level diff | `jj diff` (use `--git` for git-style output, `-s` for summary) |
| Start a new change on top of `@` | `jj new [REVISION]` (defaults to `@`) |
| Describe/set the commit message | `jj describe -m "msg"` or `jj describe` (opens editor) |
| Describe + start next change | `jj commit -m "msg"` (equivalent to `describe -m && new`) |
| View revision graph | `jj log` (use `-r` with a revset to filter, `-p` for patch) |
| Browse file in older revision | `jj file show -r REV PATH` |

`jj new` is the primary way to create changes. It creates an empty child of the given revision and makes it the new `@`. Unlike `git checkout -b`, it does not need a branch name.

When the user says "commit my changes" they almost always mean `jj describe -m "message"` to record a message on the current change, or `jj commit -m "message"` to record and start a new empty change on top.

### History restructuring

jj makes rewriting history safe because nothing is truly lost (the operation log preserves everything).

| Intent | Command |
|---|---|
| Move a change to a different parent | `jj rebase -r REV -o NEW_PARENT` |
| Move a whole branch of changes | `jj rebase -b REV -o NEW_PARENT` |
| Absorb changes from `@` into parent | `jj squash` (moves `@`'s diff into its parent) |
| Squash specific changes into sibling | `jj squash -f FROM_REV -t INTO_REV` |
| Split a revision in two | `jj split [-r REV]` (interactive by default) |
| Drop a change entirely | `jj abandon [-r REV]` (defaults to `@` if empty) |
| Rename/edit a change's description | `jj describe -r REV -m "new message"` |
| Edit a change's metadata (author, etc.) | `jj metaedit -r REV` |
| Pull edits from child into parent | `jj absorb` (auto-detects where changes belong) |
| Reorder siblings into a chain | `jj parallelize -r REVS...` |
| Interactive graph rearrangement | `jj arrange` |
| Touch up a change's content diff | `jj diffedit -r REV` |

**Common squash patterns:**
- `jj squash` — squash `@` into its parent (the most common: you made a small fix that belongs in the previous commit)
- `jj squash -f FEATURE_REV -t MAIN` — move changes from a feature revision into main

**Common rebase patterns:**
- `jj rebase -r REV -o DEST` — rebase a single revision onto DEST
- `jj rebase -b REV -o DEST` — rebase REV and all its descendants onto DEST
- `jj rebase -r REV --insert-after ANCHOR` — reorder REV to come after ANCHOR (useful for reordering commits in a stack)
- `jj rebase -r REV --insert-before ANCHOR`

When rebasing after a squash/split/abandon, jj automatically rebases descendants. You rarely need to manually restack.

### Collaboration

jj interoperates with Git remotes. The workflow is: fetch → rebase → push.

| Intent | Command |
|---|---|
| Clone a remote repo | `jj git clone <URL>` |
| Fetch from remote | `jj git fetch [--remote NAME]` |
| Push to remote | `jj git push [--remote NAME]` |
| List bookmarks and their targets | `jj bookmark list` (aliases: `b l`) |
| Track a remote bookmark as local | `jj bookmark track NAME --remote origin` |
| Move a bookmark to point at a revision | `jj bookmark move --to REV BOOKMARK` (aliases: `b m -t REV BOOKMARK`) |
| Create a new bookmark | `jj bookmark create NAME` |
| List remotes | `jj git remote list` |
| Add a remote | `jj git remote add NAME URL` |

**Push workflow:**
1. Ensure the bookmark you want to push points at your revision: `jj bookmark move --to=@ BOOKMARK`
2. Push: `jj git push`
3. If the remote has new commits: `jj git fetch` then `jj rebase -b BOOKMARK -o BOOKMARK@origin`

**Important:** Before pushing, always check the change has a description. `jj git push` will fail or warn you if a change lacks a description. Use `jj describe -m "msg"` first.

### Recovery

| Intent | Command |
|---|---|
| Undo the last operation | `jj undo` |
| Redo an undo | `jj redo` |
| See operation history | `jj op log` |
| Restore repo to a past state | `jj op restore OPERATION_ID` |
| Restore files in `@` (undo edits in wd) | `jj restore` (restores all files from parent) |
| Restore specific paths from another revision | `jj restore --from SOURCE_REV PATH...` |
| Undo the changes introduced by a commit | `jj restore --changes-in REV` (creates a reverse of REV on top of @, effectively undoing its changes) |
| Resolve conflicts | `jj resolve PATH...` (opens external merge tool) |
| Inspect old repo state without restoring | `jj --at-op OPERATION_ID status` |

`jj undo` is the first thing to reach for when something goes wrong. If you need to undo farther back, `jj op log` + `jj op restore` can take you to any previous state.

---

## Git-to-jj translation

When a user asks for a git command, translate to the equivalent jj command:

| Git | jj |
|---|---|
| `git add FILE` | Edit FILE (no staging needed — tracked files auto-included) |
| `git commit -m "msg"` | `jj describe -m "msg"` (or `jj commit -m "msg"` to also start a new change) |
| `git commit --amend` | `jj squash` (move `@`'s changes into its parent) |
| `git checkout BRANCH` | `jj new BOOKMARK` |
| `git checkout -b BRANCH` | `jj new` then `jj bookmark create NAME` |
| `git branch -d BRANCH` | `jj bookmark delete NAME` |
| `git rebase main` | `jj rebase -b @ -o MAIN` |
| `git reset HEAD~1` | `jj restore` then `jj abandon @` |
| `git revert COMMIT` | `jj restore --changes-in COMMIT` |
| `git log --oneline` | `jj log --no-graph` |
| `git stash` | Not needed — just `jj new` to start fresh on top, or `jj bookmark create` to save the current state |

---

## Choosing the right ancestor (`-o`) vs insert-after (`-A`) vs insert-before (`-B`)

- `-o` / `--onto`: makes the source revision(s) children of the target. Most common.
- `-A` / `--insert-after`: inserts the source revision(s) *after* the target, making them siblings of the target's current children. Use when reordering within a stack.
- `-B` / `--insert-before`: inserts the source revision(s) *before* the target, making them parents of the target. Use when you want to add a step before an existing commit.

These options appear on `rebase`, `new`, `split`, `squash`, and `restore`.

---

## Reference files

Read these for deeper guidance on specific workflows:

- **references/core-concepts.md** — Revsets, change IDs, working copy mechanics, configuration
- **references/daily-work.md** — Commands and patterns for the daily edit/describe/log loop
- **references/history-rewriting.md** — Detailed squash, rebase, split, abandon, and absorb patterns
- **references/collaboration.md** — Pushing, pulling, bookmark management, Gerrit
- **references/recovery.md** — Undo, operation log, conflict resolution, and restore
- **references/commands.md** — Quick reference for every jj command with key flags
