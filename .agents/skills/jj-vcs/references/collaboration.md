# Collaboration

Commands for working with Git remotes, bookmarks, and pushing/pulling changes.

## jj git clone

Clone a remote Git repository into a jj-backed repo.

```
jj git clone <URL>                    # clone and checkout default branch
jj git clone <URL> --colocate         # clone as a colocated repo (works with git commands too)
```

## jj git fetch

Fetch changes from a remote. Unlike `git fetch`, this fetches all bookmarks by default and can automatically track new bookmarks based on config.

```
jj git fetch                          # fetch all remotes
jj git fetch --remote origin          # fetch only origin
jj git fetch --remote origin main     # fetch specific bookmark(s)
```

After fetch, new remote bookmarks appear as `BOOKMARK@remote`. They aren't automatically tracked — you must explicitly `jj bookmark track` them.

## jj git push

Push changes to a remote. By default, pushes all bookmarks that have a remote counterpart.

```
jj git push                           # push all tracked bookmarks
jj git push --remote origin            # push to specific remote
jj git push --bookmark main           # push only specific bookmark(s)
jj git push --deleted BOOKMARK        # propagate a bookmark deletion
jj git push --change CHANGE_ID        # push a specific change by change ID
```

- `--bookmark` / `-b`: specify which bookmarks to push
- `--change`: push a single change to the remote as a draft PR (creates a bookmark on the remote)
- `--remote`: specify the remote
- `--deleted`: confirm you want to push a bookmark deletion to the remote

**Push checklist:**
1. The revision has a description: `jj describe -m "msg"`
2. The bookmark points at the right revision: `jj bookmark move --to=REV BOOKMARK` or use `jj bookmark set BOOKMARK` (creates or moves)
3. The revision does not have conflicts: `jj status` will show them
4. You're not upstream of others' work (if collaborating)
5. Push: `jj git push`

## jj bookmark

Bookmark management. Short alias: `jj b`.

```
jj bookmark list                  # list all bookmarks and their targets (aliases: l)
jj bookmark create NAME           # create a new bookmark at @ (aliases: c)
jj bookmark move --to REV NAME    # move bookmark NAME to point at REV (aliases: m)
jj bookmark set NAME              # create or update bookmark NAME at @ (aliases: s)
jj bookmark track NAME --remote R # track a remote bookmark locally (aliases: t)
jj bookmark untrack NAME          # stop tracking a remote bookmark
jj bookmark delete NAME           # delete a local bookmark (aliases: d)
jj bookmark forget NAME           # forget a bookmark without pushing deletion
jj bookmark advance NAME          # advance bookmark to nearest descendant of current target
jj bookmark rename OLD NEW        # rename a bookmark
```

**Bookmark workflow for pushing changes:**
1. Work in `@` (on top of main)
2. When ready: `jj bookmark move --to=@ main` (move the main bookmark to `@`)
3. `jj git push` (pushes main to origin/main)

Or use a feature-branch workflow:
1. `jj bookmark create my-feature` (creates bookmark at `@`)
2. Work, describe, etc.
3. `jj git push -b my-feature` (pushes just `my-feature`)

**Tracking:** When you clone a repo, remote bookmarks like `main@origin` exist but aren't automatically tracked. `jj bookmark track main --remote origin` creates a local `main` bookmark that follows `main@origin`. Without this, `jj git push` may not know which local bookmark corresponds to which remote bookmark.

## jj git remote

Manage Git remotes.

```
jj git remote list                # list remotes
jj git remote add NAME URL        # add a remote
jj git remote remove NAME         # remove a remote
jj git remote set-url NAME URL    # change a remote's URL
```

## jj git colocation

Manage colocation with an underlying Git repo. Colocation means the `.jj` repo works on the same working copy as a `.git` repo, allowing both `jj` and `git` commands.

```
jj git colocation init            # initialize colocation
jj git colocation deinit          # remove colocation
jj git export                     # manually sync jj changes to git
jj git import                     # manually sync git changes to jj
```

With colocation, export/import happens automatically on most commands. Use manual `jj git export` or `jj git import` if you've made changes in git that jj doesn't see yet.

## jj gerrit

Interact with Gerrit Code Review.

```
jj gerrit submit CHANGE_ID          # submit a change to Gerrit
jj gerrit abandon CHANGE_ID         # abandon a change in Gerrit
```

## Working with stacks

jj excels at stacking changes. Common pattern:

1. `jj new main` — start from main
2. `jj describe -m "part 1"` — describe first change
3. `jj new` — start second change
4. `jj describe -m "part 2"` — describe second change
5. `jj bookmark create stack-1` — save both (bookmark on latest)
6. `jj bookmark create stack-2` — or just push with `jj git push -b stack-1`

To restack after reviews:
1. `jj rebase -b stack-1 -o main` — move whole stack
2. `jj git push` — update remote
