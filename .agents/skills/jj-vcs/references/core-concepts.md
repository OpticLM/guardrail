# Core concepts

Understanding these concepts is essential for using jj correctly. Read this when the user seems new to jj, or when you need to reason about jj behavior beyond simple commands.

## Change IDs vs commit hashes

Every revision in jj has two identifiers:

- **Change ID** — A stable identifier (e.g., `abc12345`) that follows the revision across rebases, squashes, and splits. Use this when referring to a logical change over time.
- **Commit hash** — A hash of the commit content (like Git). Changes every time the diff changes. Use this when you need to reference exact content.

Commands that take revisions (almost all of them) accept change IDs, commit hashes, or revset expressions. Prefer change IDs for user-facing references since they're stable.

## The working copy (`@`)

The `@` symbol represents the working copy revision. Unlike Git's detached HEAD or branch-based model:

- `@` is always a regular commit. It can have a description, parent(s), and children.
- When you edit files, those changes belong to `@`.
- `jj new` creates a new *empty* commit on top of `@` and makes that the new `@`. The old `@` becomes `@-` (parent of working copy).
- `jj edit REV` sets the working copy to revision REV. Edits go directly into that revision's diff. Use `jj new` instead unless you specifically need to amend an existing change.
- `jj status` shows the diff between `@` and its parent (`@-`).

## Operation log

Every jj command creates an **operation** in the operation log. This is jj's safety net:

- `jj op log` shows the history of commands (like shell history but richer)
- `jj undo` creates a new operation that reverses the last one
- `jj op restore OP_ID` restores the repo to the state after a given operation
- `jj --at-op OP_ID <command>` runs a command as if the repo were at that operation (read-only inspection)

Nothing is permanently lost unless you run `jj util gc` (garbage collection). The operation log is append-only.

## Revsets

Revsets are jj's query language for selecting revisions. They appear everywhere a command accepts revisions. Key patterns:

| Expression | Meaning |
|---|---|
| `@` | The working copy revision |
| `main` | The revision pointed to by bookmark `main` |
| `main@origin` | The revision pointed to by `main` on the `origin` remote |
| `root()` | The root revision (virtual, all repos share it) |
| `all()` | Every revision in the repo |
| `mine()` | Revisions authored by the current user |
| `none()` | Empty set |
| `parents(REVSET)` | Parents of revisions in the set |
| `children(REVSET)` | Children of revisions in the set |
| `ancestors(REVSET)` | All ancestors (recursive parents) |
| `descendants(REVSET)` | All descendants (recursive children) |
| `::` | DAG range — `A::B` means "A and B and everything between them" |
| `..` | Reachable from B but not from A — `A..B` means "B and ancestors of B not also ancestors of jj" |
| `X \ Y` | Set difference |
| `X + Y` | Set union |
| `X & Y` | Set intersection |
| `empty()` | Revisions with no diff from their parent |
| `description(REGEX)` | Revisions whose description matches REGEX |
| `author("NAME")` | Revisions authored by NAME (partial match) |
| `bookmarks()` | Revisions that have bookmarks |
| `immutable_heads()` | The configured immutable set |
| `latest(N, REVSET)` | The latest N revisions in the set |
| `merged()` | Merge commits |

**Practical examples:**
- `main..@` — revisions in `@`'s ancestors that aren't in main (what you changed since main)
- `ancestors(@) & ~immutable_heads()` — everything you can safely rewrite
- `@-` — the parent of the working copy (one commit back)
- `@--` — grandparent of the working copy
- `description("fix.*")` — revisions with descriptions starting with "fix"
- `empty() & ~@` — revisions that are empty but not the working copy (candidates for abandonment)

## Bookmarks

Bookmarks are labels attached to revisions. They serve the same conceptual role as Git branches but behave differently:

- Bookmarks can coexist at the same revision (no conflict)
- Moving a bookmark doesn't affect the revision it points to — the revision keeps its change ID
- Tracking a remote bookmark (`jj bookmark track NAME --remote origin`) creates a local bookmark that follows the remote's updates
- Git branches are represented as bookmarks with `@remote` suffixes (e.g., `main@origin`)
- `jj bookmark list` shows all bookmarks; the output format is `BOOKMARK: CHANGE_ID commit_hash`

## The immutable set

By default, jj prevents rewriting commits that are ancestors of any remote-tracking bookmark. This is configured by `revsets.immutable_heads` in the config (typically `immutable_heads() & ~@` plus `bookmarks()@remote`). Use `--ignore-immutable` to bypass this check (e.g., `jj rebase --ignore-immutable -r OLD_REV`).

## Global flags

These work with any jj command:

- `--at-op OP` — run as if repo were at a past operation (read-only)
- `--ignore-immutable` — allow rewriting protected commits
- `--ignore-working-copy` — skip snapshotting the working copy (faster, but may show stale state)
- `-R PATH` — operate on a different repository
- `--config NAME=VAL` — set config options inline (TOML syntax)
