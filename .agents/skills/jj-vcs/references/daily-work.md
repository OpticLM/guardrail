# Daily work

Commands and patterns for the core edit/describe/log cycle.

## jj status

Shows the diff between the working copy (`@`) and its parent. This is the first thing to run when a user asks "what's going on?" or "what have I changed?".

Key alias: `jj st` (the most common form used in practice).

Output shows:
- Which revision you're on (change ID, commit hash, bookmark)
- Whether `@` is empty or has changes
- The diff (added/modified/deleted files)
- Any conflicts

## jj new

Creates a new empty revision as a child of the given revision (default: `@`) and makes it the working copy. This is the closest jj equivalent to starting a new branch of work.

```
jj new          # new child of @, empty, becomes new @
jj new REV      # new child of REV
jj new A B      # new merge revision with parents A and B
```

- `--insert-after REV` — insert the new revision after REV (between REV and its children)
- `--insert-before REV` — insert before REV (between REV and its parents)
- `-m "msg"` — set description immediately
- `--no-edit` — create the revision but don't switch working copy to it

## jj describe

Sets or edits the description (commit message) of a revision.

```
jj describe          # opens editor to edit @'s description
jj describe -m "msg" # set description of @ inline
jj describe -r REV   # describe a specific revision
```

- `-m "msg"` — set description from command line (no editor)
- `--stdin` — read description from stdin
- `-r REV` — describe a different revision (default: `@`)

**Important:** A revision needs a description before it can be pushed. Always use `jj describe` (not `jj commit`) when the user says "write a commit message."

## jj commit

Combines `jj describe -m "msg"` followed by `jj new`. Records the current change's description and immediately starts a fresh empty revision on top.

```
jj commit -m "feat: add user auth"
```

This is the jj equivalent of git's `commit` but note: there's no staging step. Any changes to tracked files are included.

## jj log

Shows the revision graph. This is your primary tool for understanding history.

```
jj log                    # default view (configurable via revsets.log)
jj log -r "main..@"      # changes you've made since main
jj log -r "author(me)"   # your changes
jj log -r "all()"        # everything
jj log -r REV            # log starting from REV
```

Key flags:
- `-r REVSET` — which revisions to show (revset)
- `-n N` / `--limit N` — limit to N results
- `--no-graph` — flat list (good for scripting)
- `--reversed` — oldest first
- `-p` / `--patch` — show the diff for each revision
- `-T TEMPLATE` — custom template
- `--count` — just print the count

## jj diff

Shows the diff of a revision. Unlike `jj log -p`, this focuses purely on the content diff.

```
jj diff                  # diff of @ vs its parent
jj diff -r REV           # diff of REV vs its parent
jj diff --from A --to B  # diff between two specific revisions
```

Key flags:
- `--git` — git-format diff (good for piping or review)
- `-s` / `--summary` — just show which files changed
- `--stat` — histogram of changes
- `--name-only` — just file paths
- `--color-words` — word-level diff
- `--context N` — lines of context

## jj edit

Sets the working copy to an existing revision. Edits go directly into that revision's diff — this rewrites history.

```
jj edit REV   # switch working copy to REV
```

Prefer `jj new REV` over `jj edit REV` in most cases: `jj new` creates a child so you can't accidentally rewrite the parent. Use `jj edit` when you intentionally want to amend an existing change (e.g., you forgot to include a file).

## jj file

File-level operations.

```
jj file list [-r REV]    # list tracked files in REV
jj file show -r REV PATH # show file contents from REV
jj file chmod MODE PATH  # change file mode (e.g., +x, -x)
jj file untrack PATH     # stop tracking a file (adds to .gitignore automatically)
jj file track PATH       # start tracking a file (reverses untrack)
```
