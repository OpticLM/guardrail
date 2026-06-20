# Command quick reference

Every jj command with a one-line description and key flags. Read this when you need a quick overview of what commands are available.

| Command | Description | Key flags |
|---|---|---|
| `jj abandon [-r REV]` | Drop a revision from history | `-r` revision to drop (default: `@`) |
| `jj absorb` | Auto-merge changes into their logical parent revisions | — |
| `jj arrange` | Interactively rearrange the commit graph | — |
| `jj bisect -r GOOD..BAD` | Binary search for a bad revision | Standard bisect: start, good, bad, skip |
| `jj bookmark <SUB>` | Manage bookmarks | Subcommands: list, create, delete, move, set, track, untrack, forget, advance, rename |
| `jj commit -m "msg"` | Describe `@` and create a new empty change on top | `-m`, `-i` interactive |
| `jj config <SUB>` | Manage configuration | Subcommands: get, set, edit, list, default |
| `jj describe -r REV -m "msg"` | Set or edit a revision's description | `-r` revision, `-m` message, `--stdin`, `--editor` |
| `jj diff [-r REV]` | Show diff of a revision | `-r`, `--git`, `-s` summary, `--stat`, `--name-only`, `--color-words` |
| `jj diffedit -r REV` | Edit a revision's content diff interactively | `-r`, `-i` |
| `jj duplicate -r REV` | Copy a revision's content to a new change ID | `-r` |
| `jj edit REV` | Switch working copy to an existing revision | — |
| `jj evolog -r REV` | Show how a change's content evolved over time | `-r`, `-p` patch |
| `jj file <SUB>` | File operations | Subcommands: list, show, chmod, track, untrack |
| `jj fix [-r REV]` | Apply formatting/linting tools to files in a revision | `-r`, `-s` source revsets, `--tool`, `-i` |
| `jj git <SUB>` | Git remote operations | Subcommands: clone, fetch, push, remote, init, export, import, colocation |
| `jj gerrit <SUB>` | Interact with Gerrit Code Review | Subcommands: submit, abandon |
| `jj help [CMD]` | Show help for jj or a specific command | — |
| `jj interdiff --from A --to B` | Show differences between two revisions' diffs | `--from`, `--to` |
| `jj log [-r REVSET]` | Show revision history graph | `-r`, `-n`, `--no-graph`, `-p`, `--reversed`, `--count`, `-T` template |
| `jj metaedit -r REV` | Edit revision metadata (author, date, description) | `-r`, `--reset-author` |
| `jj new [REV]...` | Create a new empty change (child of given revision) | `-m`, `--no-edit`, `--insert-after`, `--insert-before` |
| `jj next` | Move working copy to the child revision | `-e` edit the destination |
| `jj op <SUB>` | Operation log commands | Subcommands: log, restore, undo, discard, integrate |
| `jj parallelize -r REVS` | Make sibling revisions into parallel branches | `-r` |
| `jj prev` | Move working copy to the parent revision | `-e` edit the destination |
| `jj rebase -r REV -o DEST` | Move revisions to different parent(s) | `-r`, `-s`, `-b`, `-o/\!--onto`, `--insert-after`, `--insert-before`, `--skip-emptied` |
| `jj redo` | Redo the last undone operation | — |
| `jj resolve PATH...` | Resolve merge conflicts | `--list` |
| `jj restore [PATH]...` | Restore file contents (undo changes to a path or revision) | `--from`, `--into`, `--changes-in`, `-i` |
| `jj revert [-r REV]` | Apply reverse of the given revision(s) | `-r` (same as `jj restore --changes-in REV`) |
| `jj root` | Show workspace root directory | — |
| `jj show [-r REV]` | Show revision description and its diff | `-r` |
| `jj sign -r REV` | Cryptographically sign a revision | `-r` |
| `jj simplify-parents -r REV` | Remove redundant parent edges | `-r` |
| `jj sparse <SUB>` | Manage sparse checkout patterns | Subcommands: set, edit, list, clear, reset |
| `jj split [-r REV]` | Split a revision into two | `-r`, `-i`, `-m`, `--parallel`, `--insert-after`, `--insert-before` |
| `jj squash [-f FROM -t INTO]` | Move changes between revisions | `-f` from, `-t` into, `-i`, `-k` keep-emptied, `-m`, `--insert-after` |
| `jj status` | Show working copy status (aliases: `st`) | — |
| `jj tag <SUB>` | Manage tags | Subcommands: list, set, delete |
| `jj undo` | Undo the last operation | `--undo` (un-undo) |
| `jj unsign -r REV` | Drop cryptographic signature from a revision | `-r` |
| `jj util <SUB>` | Infrequently used utilities | Subcommands: gc, completion, config-schema, etc. |
| `jj version` | Show version information | — |
| `jj workspace <SUB>` | Manage workspaces | Subcommands: root, list, add, forget, upgrade |
