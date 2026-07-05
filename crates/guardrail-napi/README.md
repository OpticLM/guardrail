# @opticlm/guardrail

Native Node.js bindings for the `guardrail` cross-platform process sandbox.

This package exposes a small API:

```js
import { Sandbox } from '@opticlm/guardrail'

const sandbox = await Sandbox.build({
  fs: [
    { kind: 'read-allow', path: '/usr' },
    { kind: 'execute-allow', path: '/usr' },
    { kind: 'read-allow', path: '/etc' },
    { kind: 'read-allow', path: '/run' },
    { kind: 'read-allow', path: '/dev/null' },
    { kind: 'write-allow', path: '/dev/null' },
    { kind: 'read-allow', path: '/tmp/work' },
    { kind: 'write-allow', path: '/tmp/work' },
    { kind: 'execute-allow', path: '/tmp/work' },
  ],
  network: 'deny', // 'deny' | 'outbound-only' | 'full'
  ipc: 'strict', // 'strict' | 'relaxed'
  memoryLimitMb: 256,
  env: {
    PATH: '/usr/bin:/bin',
    HOME: '/tmp/work/home',
    TMPDIR: '/tmp/work/tmp',
    LANG: 'C.UTF-8',
    LC_ALL: 'C.UTF-8',
  },
})

const child = sandbox.spawn('/usr/bin/true')
const result = await child.wait()
// result: { code, signal, success, violation? }
```

`spawn(command, args, options)` is also available as a one-shot wrapper, but
`await Sandbox.build(options)` is preferred when running more than one command.

## Linux Setup Guide

This section is Linux-specific. It was tested on Fedora Linux 7.0.8 x86_64 with
Node 26.1.0, pnpm 11.5.1, Cargo 1.95.0, Go 1.26.4, Git 2.54.0, jj 0.41.0, and
GitHub CLI 2.92.0.

Guardrail is intentionally literal: the child sees only the filesystem,
network, IPC, resource limits, working directory, and environment you declare.
There is no inherited environment fallback.

### Baseline Policy

Start with one writable workspace root, one writable temp root, and read/execute
access to the system runtime:

```js
import { mkdir } from 'node:fs/promises'

await mkdir(workRoot, { recursive: true })
await mkdir(tmpRoot, { recursive: true })
await mkdir(`${workRoot}/home`, { recursive: true })
await mkdir(`${workRoot}/xdg-cache`, { recursive: true })
await mkdir(`${workRoot}/xdg-config`, { recursive: true })

const xdgCache = `${workRoot}/xdg-cache`
const xdgConfig = `${workRoot}/xdg-config`

const fs = [
  // Dynamic binaries, shells, system CLIs, libc, certificates, and locale data.
  { kind: 'read-allow', path: '/usr' },
  { kind: 'execute-allow', path: '/usr' },

  // Common runtime reads. Keep only paths that exist on your distribution.
  { kind: 'read-allow', path: '/etc' },
  { kind: 'read-allow', path: '/run' }, // DNS config may resolve here.
  { kind: 'read-allow', path: '/proc' },
  { kind: 'read-allow', path: '/sys' },
  { kind: 'read-allow', path: '/dev/urandom' },
  { kind: 'read-allow', path: '/dev/random' },
  { kind: 'read-allow', path: '/dev/null' },
  { kind: 'write-allow', path: '/dev/null' },

  // Your controlled area.
  { kind: 'read-allow', path: workRoot },
  { kind: 'write-allow', path: workRoot },
  { kind: 'execute-allow', path: workRoot },
  { kind: 'read-allow', path: tmpRoot },
  { kind: 'write-allow', path: tmpRoot },
  { kind: 'execute-allow', path: tmpRoot },
]

const env = {
  PATH: '/usr/bin:/bin',
  HOME: `${workRoot}/home`,
  TMPDIR: tmpRoot,
  LANG: 'C.UTF-8',
  LC_ALL: 'C.UTF-8',
}
```

Notes:

- Create every path you put in `fs` before calling `Sandbox.build()`. On Linux,
  Guardrail canonicalizes rule paths while building the Landlock policy, so a
  missing workspace, cache, or temp directory fails closed before the child is
  spawned.
- `execute-allow` does not imply `read-allow`. Most dynamic binaries need both
  for the executable, dynamic loader, and shared libraries.
- `write-allow` does not imply `read-allow`.
- Keep writable tool caches inside your controlled roots. Do not point
  `CARGO_HOME`, `GOCACHE`, `GOMODCACHE`, `PNPM_HOME`, npm cache, or XDG cache at
  your real home directory unless you intentionally want the sandboxed command
  to read or mutate those paths.
- Avoid overlapping writable grants unless you need a later deny/allow
  exception. A single writable parent such as `workRoot` is easier to reason
  about than separate writable grants for every child directory.
- For commands that print a lot of output, redirect logs into `workRoot`.
  `guardrail-napi` currently inherits stdio and does not provide output capture.

### Coreutils

For tools such as `ls`, `cat`, and `grep`, the baseline policy is enough when
the target files live under `workRoot`:

```js
const sandbox = await Sandbox.build({
  fs,
  env,
  network: 'deny',
  ipc: 'strict',
})

await sandbox.spawn('/usr/bin/grep', ['-q', 'needle', 'alpha.txt'], {
  cwd: `${workRoot}/coreutils-demo`,
}).wait()
```

### Cargo

Use the real Rust sysroot as read/execute input, but put Cargo state and build
artifacts under the sandbox workspace:

```js
const rustSysroot = '/home/me/.rustup/toolchains/stable-x86_64-unknown-linux-gnu'
const cargoHome = `${workRoot}/cargo-home`
const targetDir = `${workRoot}/rust-project/target`

const cargoSandbox = await Sandbox.build({
  fs: [
    ...fs,
    { kind: 'read-allow', path: rustSysroot },
    { kind: 'execute-allow', path: rustSysroot },
    { kind: 'read-allow', path: cargoHome },
    { kind: 'write-allow', path: cargoHome },
    { kind: 'execute-allow', path: cargoHome },
  ],
  env: {
    ...env,
    PATH: `${rustSysroot}/bin:/usr/bin:/bin`,
    CARGO_HOME: cargoHome,
    CARGO_TARGET_DIR: targetDir,
    CARGO_TERM_COLOR: 'never',
  },
  network: 'deny',
  ipc: 'strict',
})

await cargoSandbox.spawn(`${rustSysroot}/bin/cargo`, ['build', '--offline'], {
  cwd: `${workRoot}/rust-project`,
}).wait()
```

Tested result: a dependency-free Rust binary builds successfully with
`cargo build --offline`.

Current Linux backend limitation: `cargo fetch` needs `network: 'full'` on this
backend, not `outbound-only`. Building a downloaded dependency can still fail
with `Invalid cross-device link (os error 18)` while rustc persists artifacts.
This comes from Landlock cross-directory link/rename behavior in the current
backend; it is not fixed by broader filesystem grants.

### pnpm

pnpm needs read/execute access to the pnpm installation plus writable project,
store, npm cache, XDG cache/config, home, and temp paths. On this backend,
`pnpm add` also needs `network: 'full'`.

```js
const pnpmHome = '/home/me/.local/share/pnpm'
const pnpmStore = `${workRoot}/pnpm-store`
const pnpmCache = `${workRoot}/pnpm-cache`
const xdgCache = `${workRoot}/xdg-cache`
const xdgConfig = `${workRoot}/xdg-config`

const pnpmSandbox = await Sandbox.build({
  fs: [
    ...fs,
    { kind: 'read-allow', path: pnpmHome },
    { kind: 'execute-allow', path: pnpmHome },
    { kind: 'read-allow', path: pnpmStore },
    { kind: 'write-allow', path: pnpmStore },
    { kind: 'execute-allow', path: pnpmStore },
    { kind: 'read-allow', path: pnpmCache },
    { kind: 'write-allow', path: pnpmCache },
    { kind: 'execute-allow', path: pnpmCache },
    { kind: 'read-allow', path: xdgCache },
    { kind: 'write-allow', path: xdgCache },
    { kind: 'execute-allow', path: xdgCache },
    { kind: 'read-allow', path: xdgConfig },
    { kind: 'write-allow', path: xdgConfig },
    { kind: 'execute-allow', path: xdgConfig },
  ],
  env: {
    ...env,
    PATH: `${pnpmHome}/bin:/usr/bin:/bin`,
    PNPM_HOME: pnpmHome,
    npm_config_cache: pnpmCache,
    npm_config_update_notifier: 'false',
    XDG_CACHE_HOME: xdgCache,
    XDG_CONFIG_HOME: xdgConfig,
    CI: '1',
  },
  network: 'full',
  ipc: 'strict',
})

await pnpmSandbox.spawn(
  `${pnpmHome}/bin/pnpm`,
  ['add', 'is-number@7.0.0', '--store-dir', pnpmStore],
  { cwd: `${workRoot}/node-project` },
).wait()
```

Tested result: `pnpm add is-number@7.0.0` completed successfully.

### Go

Use `/usr/bin/go` or the resolved Go binary, grant read/execute access to
`GOROOT`, and keep all writable Go state in the sandbox workspace:

```js
const goRoot = '/usr/lib/golang'
const goPath = `${workRoot}/go-path`
const goCache = `${workRoot}/go-cache`
const goModCache = `${workRoot}/go-mod-cache`

const goSandbox = await Sandbox.build({
  fs: [
    ...fs,
    { kind: 'read-allow', path: goRoot },
    { kind: 'execute-allow', path: goRoot },
    { kind: 'read-allow', path: goPath },
    { kind: 'write-allow', path: goPath },
    { kind: 'execute-allow', path: goPath },
    { kind: 'read-allow', path: goCache },
    { kind: 'write-allow', path: goCache },
    { kind: 'execute-allow', path: goCache },
    { kind: 'read-allow', path: goModCache },
    { kind: 'write-allow', path: goModCache },
    { kind: 'execute-allow', path: goModCache },
  ],
  env: {
    ...env,
    GOROOT: goRoot,
    GOPATH: goPath,
    GOCACHE: goCache,
    GOMODCACHE: goModCache,
    GOTOOLCHAIN: 'local',
  },
  network: 'deny',
  ipc: 'strict',
})

await goSandbox.spawn('/usr/bin/go', ['build', './...'], {
  cwd: `${workRoot}/go-project`,
}).wait()
```

Tested result: `go build ./...` completed successfully for a local module with
no external downloads.

### Git

Git works with the baseline policy plus a writable config home. Keep repository
contents under `workRoot`.

```js
const gitSandbox = await Sandbox.build({
  fs: [
    ...fs,
    { kind: 'read-allow', path: xdgConfig },
    { kind: 'write-allow', path: xdgConfig },
    { kind: 'execute-allow', path: xdgConfig },
  ],
  env: {
    ...env,
    XDG_CONFIG_HOME: xdgConfig,
  },
  network: 'deny',
  ipc: 'strict',
})

await gitSandbox.spawn('/usr/bin/git', ['init'], {
  cwd: `${workRoot}/repo`,
}).wait()
await gitSandbox.spawn('/usr/bin/git', ['status', '--short'], {
  cwd: `${workRoot}/repo`,
}).wait()
```

Tested result: `git init` and `git status --short` completed successfully.

### jj

Read-only jj inspection can work, but pass `--ignore-working-copy` so jj does
not snapshot the working copy:

```js
const jjBin = '/home/me/.cargo/bin/jj'

const jjSandbox = await Sandbox.build({
  fs: [
    ...fs,
    { kind: 'read-allow', path: '/home/me/.cargo/bin' },
    { kind: 'execute-allow', path: '/home/me/.cargo/bin' },
    { kind: 'read-allow', path: xdgConfig },
    { kind: 'write-allow', path: xdgConfig },
    { kind: 'execute-allow', path: xdgConfig },
  ],
  env: {
    ...env,
    PATH: `/home/me/.cargo/bin:/usr/bin:/bin`,
    XDG_CONFIG_HOME: xdgConfig,
  },
  network: 'deny',
  ipc: 'strict',
})

await jjSandbox.spawn(jjBin, ['--ignore-working-copy', 'status'], {
  cwd: `${workRoot}/repo`,
}).wait()
```

Tested result: `jj --ignore-working-copy status`, `jj --ignore-working-copy log`,
and `jj root` completed successfully against an existing jj repo.

Current Linux backend limitation: `jj git init`, default `jj status`, and
commands that snapshot or write commits can fail with `Invalid cross-device link
(os error 18)` while writing Git objects. This matches Landlock's cross-directory
link/rename restriction for the backend's current ABI choice.

### GitHub CLI (`gh`)

For local commands such as `gh --version`, the baseline policy plus writable
home/XDG cache/config paths is enough. API calls need outbound network.

```js
const ghSandbox = await Sandbox.build({
  fs: [
    ...fs,
    { kind: 'read-allow', path: xdgCache },
    { kind: 'write-allow', path: xdgCache },
    { kind: 'execute-allow', path: xdgCache },
    { kind: 'read-allow', path: xdgConfig },
    { kind: 'write-allow', path: xdgConfig },
    { kind: 'execute-allow', path: xdgConfig },
  ],
  env: {
    ...env,
    XDG_CACHE_HOME: xdgCache,
    XDG_CONFIG_HOME: xdgConfig,
    // Add GH_TOKEN here if you want authenticated API calls.
  },
  network: 'outbound-only',
  ipc: 'strict',
})

await ghSandbox.spawn('/usr/bin/gh', ['api', 'rate_limit', '--jq', '.resources.core.limit'], {
  cwd: workRoot,
}).wait()
```

Tested result: `gh --version` completed with `network: 'deny'`, and
`gh api rate_limit --jq .resources.core.limit` completed with
`network: 'outbound-only'`.

## Diagnostics

`wait()` resolves to `{ code, signal, success, violation? }`. Diagnostics are
best-effort hints from the native backend:

```js
const result = await child.wait()
if (!result.success && result.violation) {
  console.error(result.violation.summary)
  for (const suggestion of result.violation.suggestions) {
    console.error(`  - ${suggestion}`)
  }
}
```

On Linux, a bad system call usually means the seccomp network or IPC policy is
too tight for the tool. A plain nonzero exit with "Permission denied" or
`Invalid cross-device link` in the tool's stderr usually means a filesystem
grant or current Landlock limitation is involved.

## API Notes

- The sandbox denies everything by default. Grant exactly the access the child
  needs.
- Filesystem rules are applied in array order. Later matching rules override
  earlier matching rules for the same right.
- `stdio` is inherited from the parent process. Output capture is not yet
  supported.
- `cwd` is passed per spawn:

  ```js
  const child = sandbox.spawn('/usr/bin/mytool', ['--flag'], { cwd: workRoot })
  ```

- `child.kill()` is best-effort once `wait()` is in flight: it sends SIGKILL on
  Unix and is unsupported on Windows in that state.
- `windowsCacheNamespace` is Windows-only and ignored on Linux.
- `darwinSandboxProfiles` is macOS-only and ignored on Linux.
