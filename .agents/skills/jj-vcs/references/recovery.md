# Recovery

Commands for undoing mistakes, resolving conflicts, and restoring lost work.

## jj undo

Undoes the most recent operation. This is the first recovery command to reach for.

```
jj undo                     # undo last operation
jj undo --undo              # undo the undo (same as jj redo)
```

Any operation can be undone — commit, rebase, push, etc. The undo itself creates a new operation, so it can also be undone.

## jj redo

Redo the most recently undone operation.

```
jj redo                     # redo last undo
```

## jj op log / jj operation

View the operation log — the history of all jj commands run in this repo. This is jj's equivalent of shell history but tied to repo state.

```
jj op log                   # show all operations
jj op log -n 20             # show last 20 operations
```

Each operation has an ID (hash). The most recent operation is shown at the top with `@`. The snapshot of the working copy is also an operation.

## jj op restore

Restore the repo to a previous state by operation. Unlike `jj undo` (which only undoes the last operation), this can jump to any point in the operation log.

```
jj op restore OP_ID         # restore repo to state after OP_ID
jj op restore --what undo   # restore just the undo history (not working copy)
```

This is *not* a revert — it moves the entire repo state backward (or forward). Changes made after that operation will appear as divergent changes. Use `jj --at-op` for read-only inspection first.

## jj restore (content restore)

Restore file contents within a revision. This is NOT the same as `jj op restore`.

```
jj restore                    # restore all files in @ from its parent
jj restore PATH               # restore specific files in @ from its parent
jj restore --from SOURCE      # restore from a specific source revision
jj restore --changes-in REV   # undo the changes introduced by REV (creates reverse diff on @)
```

- Without `--from`: restores from the parent of the target revision
- Without `--into`: restores into `@`
- `--changes-in REV` is the closest equivalent to `git revert REV` — it applies the reverse of REV's diff to `@`
- `--restore-descendants`: when rebasing descendants, preserve their content (not their diff)

To "unstage" files (there's no real staging area in jj, but for git users who ask): use `jj restore PATH` to undo changes to specific files in `@`.

## jj resolve

Resolve merge conflicts. jj tracks conflicts natively (unlike git, which leaves conflict markers in files and lets you handle them).

```
jj resolve PATH...            # resolve conflicts in specific files
jj resolve --list             # list all unresolved conflicts
```

When you run `jj resolve`, jj opens the external merge tool (configured in `merge-tools`). If no tool is configured, it falls back to leaving conflict markers in the file, which you can edit manually.

After resolving conflicts manually (by editing the file), mark them as resolved with `jj resolve PATH`.

## jj --at-op (read-only inspection)

Run any jj command as if the repo were at a past operation. Read-only — useful for inspecting old state before deciding whether to restore.

```
jj --at-op OP_ID log          # log from past state
jj --at-op OP_ID status       # status from past state
jj --at-op OP_ID diff -r REV  # diff from past state
```

## Divergent changes

When the operation log has diverged (e.g., two concurrent operations), `jj status` will warn about divergent operations. This happens when you run jj commands from different terminals or after `jj op restore`.

To resolve divergence:
1. `jj --at-op OP_ID status` for each divergent operation to understand the state
2. `jj op restore` to pick one side
3. Or use `jj new` to create a merge of the divergent states

## Common recovery scenarios

**"I rebased and lost changes"**
- `jj undo` — undoes the rebase
- If `jj undo` isn't enough: `jj op log` to find the pre-rebase operation, then `jj op restore OP_ID`

**"I pushed the wrong thing"**
- You can't unpush (remote doesn't support it), but you can:
  1. Fix the local revision
  2. `jj bookmark move --to=FIXED BOOKMARK`
  3. `jj git push --force` or `jj git push` with a new commit

**"I accidentally squashed the wrong files"**
- `jj undo` immediately
- If too late: use the operation log to find the pre-squash state

**"I want to get old version of a file back"**
- `jj restore --from OLD_REV PATH` — restore PATH from OLD_REV into `@`
- Or: `jj file show -r OLD_REV PATH > PATH` to extract it as a file

**"jj status shows conflicts"**
- `jj resolve --list` to see which files have conflicts
- Resolve them individually: `jj resolve PATH`
- After resolving all, `jj status` will clear
