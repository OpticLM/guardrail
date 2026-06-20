# History rewriting

Commands for restructuring the commit graph. jj's operation log makes history rewriting safe — nothing is permanently lost.

## jj rebase

Move revisions to different parent(s). The most fundamental history-rewriting command.

```
jj rebase -r REV -o DEST       # rebase single revision REV onto DEST
jj rebase -b REV -o DEST       # rebase REV and all its descendants onto DEST
jj rebase -r REV --insert-after ANCHOR  # reorder: put REV after ANCHOR
jj rebase -r REV --insert-before ANCHOR # reorder: put REV before ANCHOR
```

Moving `-r` vs `-b`:
- `-r REV` — rebase only REV; its descendants follow because jj automatically rebases them on top
- `-b REV` — rebase the entire branch (REV and all its descendants) to a new location. Equivalent to `-s roots(dest..REV)`

Note: jj automatically rebases descendants so you don't need to manually restack after a rebase. However, this can create duplicate commits if the destination already has commits with the same change IDs. `--keep-divergent` controls this behavior.

## jj squash

Move changes from one revision into another. The most common pattern is moving `@`'s changes into its parent (the jj equivalent of amending).

```
jj squash                          # squash @ into its parent
jj squash -f SOURCE -t DEST        # move SOURCE's changes into DEST
```

- Without flags: squash `@` into `@-` (the parent). After this, `@` becomes empty and `@-` now includes the changes.
- `-f` / `--from`: which revision to take changes from (default: `@`)
- `-t` / `--into`: which revision to put changes into (default: `@`)
- `-i` / `--interactive`: choose which parts of the diff to squash
- `-k` / `--keep-emptied`: don't abandon the source revision after squashing
- `-m "msg"`: set description on the result

The `-o` (experimental), `--insert-after`, and `--insert-before` flags control where the resulting revision goes in the graph, similar to `jj rebase`.

## jj split

Split one revision into two. Changes in the original revision are partitioned into two new revisions.

```
jj split -r REV    # interactively choose which files go into the first split
jj split FILE...   # put specified files into the new first revision
```

- `-r REV`: the revision to split (default: `@`)
- `-i`: force interactive mode (choose which hunks go where)
- `-m "msg"`: description for the new (first) revision
- `--parallel`: split into two parallel revisions (same parent) instead of parent-child
- `--insert-after` / `--insert-before` / `-o`: control where the new revision goes

## jj abandon

Drop a revision. The revision is removed from the graph and its descendants are rebased onto its parent(s).

```
jj abandon -r REV   # abandon a specific revision
jj abandon          # abandon @ (only works if @ is empty)
```

Common use: clean up empty revisions after squash/restructuring. `jj abandon -r empty()` is a batch cleanup pattern.

## jj absorb

Automatically moves changes from child revisions into the parent revisions they logically belong to. It detects which changes should have been made in which parent by analyzing the diff.

```
jj absorb
```

Runs on `@` by default. Useful when you make a fix that should belong to a lower commit in your stack — instead of manually squashing, `jj absorb` figures out where each hunk belongs.

## jj parallelize

Make sibling revisions into a linear chain or vice versa.

```
jj parallelize -r REVS...
```

Takes a set of revisions and makes them siblings (all children of the same parent), rebasing their descendants as needed.

## jj arrange

Interactive graph rearrangement. Opens a diff editor where you can drag and drop revisions to reorder them. More visual than command-line rebase operations.

```
jj arrange
```

## jj diffedit

Touch up the content changes in a revision. Opens an editor showing the revision's diff and lets you modify it directly.

```
jj diffedit -r REV
```

Use this when you need to change what a specific revision does, rather than adding a fix on top.

## jj metaedit

Modify a revision's metadata (author, author date, committer, description) without changing its content.

```
jj metaedit -r REV
```

## jj restack

This is not a real command — jj restacks automatically. You should never need to manually restack after rebase, squash, etc. If a rebase leaves empty commits, `jj abandon` them.

## jj squash/absorb vs jj squash

- Use `jj squash` when you want to explicitly move changes between revisions
- Use `jj absorb` when you want jj to figure out where changes belong automatically

## jj squash vs git commit --amend

- `jj squash` without arguments is jj's equivalent of `git commit --amend`: it takes `@`'s changes and merges them into `@-`, leaving `@` empty
- Unlike git, the old `@`'s change ID still exists (as an empty revision) — you can `jj abandon` it afterwards

## jj split + jj rebase

A common pattern: split a large revision into two, then rebase one of them to a different parent:
1. `jj split -r BIG_COMMIT` — split into two
2. `jj rebase -r NEW_REV -o DIFFERENT_PARENT` — move the new revision elsewhere
