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
  linuxIpc: 'strict', // Linux-only: 'strict' | 'relaxed'
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
// result: { code, signal, success }
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
  linuxIpc: 'strict',
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
  linuxIpc: 'strict',
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
  linuxIpc: 'strict',
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
  linuxIpc: 'strict',
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
  linuxIpc: 'strict',
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
  linuxIpc: 'strict',
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
  linuxIpc: 'strict',
})

await ghSandbox.spawn('/usr/bin/gh', ['api', 'rate_limit', '--jq', '.resources.core.limit'], {
  cwd: workRoot,
}).wait()
```

Tested result: `gh --version` completed with `network: 'deny'`, and
`gh api rate_limit --jq .resources.core.limit` completed with
`network: 'outbound-only'`.

## macOS Setup Guide

This section is macOS-specific. It was tested on Darwin 24.6.0 arm64 with Node
24.15.0, pnpm 11.7.0, Cargo 1.96.0, Go 1.26.4, Git 2.53.0, jj 0.43.0, and
GitHub CLI 2.96.0.

macOS uses Seatbelt profiles. Guardrail still generates a literal `(deny
default)` profile from your `fs` and `network` options, but macOS
developer tools also need a few runtime operations that are not filesystem
paths. Use `darwinSandboxProfiles` to import those explicit `.sb` grants.

### Imported Profiles Are Authoritative

Treat every imported profile as trusted sandbox policy. Guardrail emits imports
before its generated `(deny default)`, `fs`, and `network` rules. An imported
`allow` can therefore grant access absent from the portable options, including
filesystem paths not listed in `fs`; the generated rules do not narrow or
revoke that access.

Audit every rule and transitive import. Prefer `fs` for filesystem access and
keep custom profiles limited to narrow runtime grants such as specific sysctls
and Mach lookups. A broad built-in profile can import additional broad policy,
so re-audit it on every macOS release you support.

### Built-in Profile Choice

Use Apple's built-in `dyld-support.sb` as the first imported profile:

```js
const darwinRuntimeProfile =
  '/System/Library/Sandbox/Profiles/dyld-support.sb'
```

This was the narrowest useful built-in preset found under
`/System/Library/Sandbox/Profiles`: it let a dynamically linked `/usr/bin/true`
run when paired with explicit Guardrail read/execute grants. `bsd.sb` also ran
that probe, but imports `system.sb` and grants a much broader set of system
reads, sysctls, IPC, and Mach lookups. `application.sb` and `container.sb`
expect Apple app-sandbox parameters that Guardrail does not provide, and failed
as imports in this setup.

Apple marks these system profiles as private interface, so treat the path as a
tested macOS baseline, not a stable public API. Re-test it on each macOS release
you support.

### Baseline Policy

Start with one writable workspace root, one writable temp root, explicit system
runtime reads, and `dyld-support.sb`:

```js
import { mkdir, writeFile } from 'node:fs/promises'

const profileRoot = `${workRoot}-profiles`

await mkdir(workRoot, { recursive: true })
await mkdir(tmpRoot, { recursive: true })
await mkdir(profileRoot, { recursive: true })
await mkdir(`${workRoot}/home`, { recursive: true })
await mkdir(`${workRoot}/xdg-cache`, { recursive: true })
await mkdir(`${workRoot}/xdg-config`, { recursive: true })

const xdgCache = `${workRoot}/xdg-cache`
const xdgConfig = `${workRoot}/xdg-config`
const darwinRuntimeProfile =
  '/System/Library/Sandbox/Profiles/dyld-support.sb'

const fs = [
  // Shells, system CLIs, dyld/libSystem, frameworks, certificates, and DNS.
  { kind: 'read-allow', path: '/bin' },
  { kind: 'execute-allow', path: '/bin' },
  { kind: 'read-allow', path: '/usr/bin' },
  { kind: 'execute-allow', path: '/usr/bin' },
  { kind: 'read-allow', path: '/usr/lib' },
  { kind: 'execute-allow', path: '/usr/lib' },
  { kind: 'read-allow', path: '/System' },
  { kind: 'execute-allow', path: '/System' },
  { kind: 'read-allow', path: '/etc' },
  { kind: 'read-allow', path: '/private/etc' },
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

- Use real macOS paths. `/tmp` is normally a symlink to `/private/tmp`; using a
  resolved `workRoot` and `tmpRoot` makes the profile easier to reason about.
- Create every workspace, profile, home, cache, config, and temp directory
  before calling `Sandbox.build()`. Missing imported `.sb` paths fail while
  building the backend.
- Keep imported `.sb` files outside any path the child can write. The backend
  validates imports during `Sandbox.build()`, but Seatbelt still imports by path
  when each child applies the profile.
- Imported profiles are not constrained by `fs` or `network`. An imported
  `allow` remains authoritative even when the portable options omit or deny the
  same access.
- Keep mutable tool state under `workRoot`. Do not point `HOME`, `CARGO_HOME`,
  `GOCACHE`, `GOMODCACHE`, `PNPM_HOME`, npm cache, or XDG cache/config at your
  real home directory unless you want the sandboxed tool to read or mutate it.
- `network: 'outbound-only'` is enough for HTTPS client requests on macOS in
  these tests. Use `network: 'full'` only for tools that need inbound sockets.
- `linuxIpc` is Linux-only and ignored on macOS. Seatbelt starts from `(deny
  default)`, so Mach lookups and POSIX/SysV IPC need explicit imported `.sb`
  grants.
  Note that `network: 'outbound-only'` and `'full'` also permit connecting to
  local Unix-domain sockets — Seatbelt treats those as network operations.

### Developer Tool Profile

Many developer tools fork helper processes and query sysctls. `dyld-support.sb`
alone was enough for `grep`, but Cargo aborted with `SIGABRT` and pnpm exited
128 without the extra profile below.

Create this small profile in a non-writable setup area and import it after
`dyld-support.sb` for Cargo, pnpm, Go, Git, jj, and `gh`:

```js
const devToolsProfile = `${profileRoot}/guardrail-dev-tools.sb`

await writeFile(
  devToolsProfile,
  `(version 1)
(allow process-fork)
(allow signal (target self) (target children))
(allow sysctl-read)
(allow file-read-metadata)
(allow file-test-existence)
`,
)

const darwinDeveloperProfiles = [darwinRuntimeProfile, devToolsProfile]
```

This is intentionally literal. If `allow sysctl-read` is too broad for your
threat model, replace it with the exact `(sysctl-name "...")` grants your
workload needs after tracing failures on your target macOS version.

### Coreutils

For tools such as `ls`, `cat`, and `grep`, the baseline policy plus
`dyld-support.sb` is enough when target files live under `workRoot`:

```js
const sandbox = await Sandbox.build({
  fs,
  env,
  network: 'deny',
  darwinSandboxProfiles: [darwinRuntimeProfile],
})

await sandbox.spawn('/usr/bin/grep', ['-q', 'needle', 'alpha.txt'], {
  cwd: `${workRoot}/coreutils-demo`,
}).wait()
```

Tested result: `grep -q needle alpha.txt` completed successfully.

### Cargo

Use the real Rust sysroot as read/execute input, grant the Xcode or Command
Line Tools developer directory for the linker and SDK, and keep Cargo state and
build artifacts under the sandbox workspace:

```js
const rustSysroot =
  '/Users/me/.rustup/toolchains/stable-aarch64-apple-darwin'
const xcodeDeveloperDir = '/Applications/Xcode.app/Contents/Developer'
const sdkRoot =
  `${xcodeDeveloperDir}/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk`
const clang =
  `${xcodeDeveloperDir}/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang`
const rustTriple = 'aarch64-apple-darwin' // x86_64-apple-darwin on Intel Macs.
const cargoHome = `${workRoot}/cargo-home`
const targetDir = `${workRoot}/rust-project/target`

const cargoSandbox = await Sandbox.build({
  fs: [
    ...fs,
    { kind: 'read-allow', path: rustSysroot },
    { kind: 'execute-allow', path: rustSysroot },
    { kind: 'read-allow', path: xcodeDeveloperDir },
    { kind: 'execute-allow', path: xcodeDeveloperDir },
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
    RUSTUP_TOOLCHAIN: 'stable-aarch64-apple-darwin',
    SDKROOT: sdkRoot,
    [`CARGO_TARGET_${rustTriple.toUpperCase().replaceAll('-', '_')}_LINKER`]:
      clang,
  },
  network: 'deny',
  darwinSandboxProfiles: darwinDeveloperProfiles,
})

await cargoSandbox.spawn(`${rustSysroot}/bin/cargo`, ['build', '--offline'], {
  cwd: `${workRoot}/rust-project`,
}).wait()
```

Tested result: a dependency-free Rust binary built successfully with
`cargo build --offline`.

### pnpm

pnpm needs read/execute access to the pnpm installation and to the Node runtime
it executes, plus writable project, store, npm cache, XDG cache/config, home,
and temp paths. Package downloads worked with `network: 'outbound-only'`.

```js
const nodeRoot = '/Users/me/.nvm/versions/node/v24.15.0'
const pnpmRoot = '/Users/me/Library/pnpm'
const pnpmStore = `${workRoot}/pnpm-store`
const pnpmCache = `${workRoot}/pnpm-cache`
const pnpmHome = `${workRoot}/pnpm-home`

await mkdir(pnpmHome, { recursive: true })

const pnpmSandbox = await Sandbox.build({
  fs: [
    ...fs,
    { kind: 'read-allow', path: nodeRoot },
    { kind: 'execute-allow', path: nodeRoot },
    { kind: 'read-allow', path: pnpmRoot },
    { kind: 'execute-allow', path: pnpmRoot },
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
    PATH: `${pnpmRoot}/bin:/usr/bin:/bin`,
    PNPM_HOME: pnpmHome,
    npm_config_cache: pnpmCache,
    npm_config_update_notifier: 'false',
    XDG_CACHE_HOME: xdgCache,
    XDG_CONFIG_HOME: xdgConfig,
    CI: '1',
  },
  network: 'outbound-only',
  darwinSandboxProfiles: darwinDeveloperProfiles,
})

await pnpmSandbox.spawn(
  `${pnpmRoot}/bin/pnpm`,
  ['add', 'is-number@7.0.0', '--store-dir', pnpmStore],
  { cwd: `${workRoot}/node-project` },
).wait()
```

Tested result: `pnpm add is-number@7.0.0` and
`pnpm add left-pad@1.3.0` completed successfully with
`network: 'outbound-only'`.

### Go

Grant read/execute access to `GOROOT`, keep writable Go state in the sandbox
workspace, and set `GOTOOLCHAIN: 'local'` so Go does not try to download a
different toolchain. The example below disables cgo; if you enable cgo, also
grant the Xcode developer directory and SDK as in the Cargo section.

```js
const goRoot = '/usr/local/go' // or /opt/homebrew/opt/go/libexec
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
    PATH: `${goRoot}/bin:/usr/bin:/bin`,
    GOROOT: goRoot,
    GOPATH: goPath,
    GOCACHE: goCache,
    GOMODCACHE: goModCache,
    GOTOOLCHAIN: 'local',
    CGO_ENABLED: '0',
  },
  network: 'deny',
  darwinSandboxProfiles: darwinDeveloperProfiles,
})

await goSandbox.spawn(`${goRoot}/bin/go`, ['build', './...'], {
  cwd: `${workRoot}/go-project`,
}).wait()
```

Tested result: `go build ./...` completed successfully for a local module with
no external downloads.

### Git

Git works with the baseline policy, the developer tool profile, a readable
Git installation, and writable config/cache paths. Keep repository contents
under `workRoot`.

```js
const gitRoot = '/opt/homebrew/opt/git' // or another resolved Git install root.
const gitBin = `${gitRoot}/bin/git`

const gitSandbox = await Sandbox.build({
  fs: [
    ...fs,
    { kind: 'read-allow', path: gitRoot },
    { kind: 'execute-allow', path: gitRoot },
    { kind: 'read-allow', path: xdgConfig },
    { kind: 'write-allow', path: xdgConfig },
    { kind: 'execute-allow', path: xdgConfig },
  ],
  env: {
    ...env,
    PATH: `${gitRoot}/bin:/usr/bin:/bin`,
    XDG_CONFIG_HOME: xdgConfig,
  },
  network: 'deny',
  darwinSandboxProfiles: darwinDeveloperProfiles,
})

await gitSandbox.spawn(gitBin, ['init'], {
  cwd: `${workRoot}/repo`,
}).wait()
await gitSandbox.spawn(gitBin, ['status', '--short'], {
  cwd: `${workRoot}/repo`,
}).wait()
```

Tested result: `git init` and `git status --short` completed successfully.

### jj

jj works with the same developer tool profile. Keep jj config in the sandbox or
pass identity with `--config` for commands that create commits. For prompt-like
read-only status, pass `--ignore-working-copy` so jj does not snapshot the
working copy.

```js
const jjRoot = '/Users/me/.cargo'
const jjBin = `${jjRoot}/bin/jj`
const jjConfig = [
  '--config',
  'user.name="Guardrail"',
  '--config',
  'user.email="guardrail@example.invalid"',
]

const jjSandbox = await Sandbox.build({
  fs: [
    ...fs,
    { kind: 'read-allow', path: jjRoot },
    { kind: 'execute-allow', path: jjRoot },
    { kind: 'read-allow', path: xdgConfig },
    { kind: 'write-allow', path: xdgConfig },
    { kind: 'execute-allow', path: xdgConfig },
  ],
  env: {
    ...env,
    PATH: `${jjRoot}/bin:/usr/bin:/bin`,
    XDG_CONFIG_HOME: xdgConfig,
  },
  network: 'deny',
  darwinSandboxProfiles: darwinDeveloperProfiles,
})

await jjSandbox.spawn(jjBin, [...jjConfig, 'git', 'init', '--colocate'], {
  cwd: `${workRoot}/jj-repo`,
}).wait()
await jjSandbox.spawn(
  jjBin,
  [...jjConfig, '--ignore-working-copy', 'status'],
  { cwd: `${workRoot}/jj-repo` },
).wait()
await jjSandbox.spawn(
  jjBin,
  [...jjConfig, '--ignore-working-copy', '--no-pager', 'log'],
  { cwd: `${workRoot}/jj-repo` },
).wait()
```

Tested result: `jj git init --colocate`, `jj --ignore-working-copy status`, and
`jj --ignore-working-copy --no-pager log` completed successfully.

### GitHub CLI (`gh`)

Local commands such as `gh --version` work with `network: 'deny'`. API calls
need `network: 'outbound-only'` and a `GH_TOKEN` or existing credentials inside
the sandboxed environment; otherwise `gh api` exits before making the request.

```js
const ghRoot = '/opt/homebrew/opt/gh'
const ghBin = `${ghRoot}/bin/gh`
const ghEnv = {
  ...env,
  PATH: `${ghRoot}/bin:/usr/bin:/bin`,
  XDG_CACHE_HOME: xdgCache,
  XDG_CONFIG_HOME: xdgConfig,
}

if (process.env.GH_TOKEN) {
  ghEnv.GH_TOKEN = process.env.GH_TOKEN
}

const ghSandbox = await Sandbox.build({
  fs: [
    ...fs,
    { kind: 'read-allow', path: ghRoot },
    { kind: 'execute-allow', path: ghRoot },
    { kind: 'read-allow', path: xdgCache },
    { kind: 'write-allow', path: xdgCache },
    { kind: 'execute-allow', path: xdgCache },
    { kind: 'read-allow', path: xdgConfig },
    { kind: 'write-allow', path: xdgConfig },
    { kind: 'execute-allow', path: xdgConfig },
  ],
  env: ghEnv,
  network: 'outbound-only',
  darwinSandboxProfiles: darwinDeveloperProfiles,
})

await ghSandbox.spawn(
  ghBin,
  ['api', 'rate_limit', '--jq', '.resources.core.limit'],
  { cwd: workRoot },
).wait()
```

Tested result: `gh --version` completed successfully with `network: 'deny'`.
This test host had no `GH_TOKEN`, so `gh api rate_limit` exited with GitHub
CLI's authentication prompt both outside and inside Guardrail. The same macOS
policy and `network: 'outbound-only'` completed an HTTPS request to
`https://api.github.com/rate_limit` with `/usr/bin/curl`.

## Platform Capability Matrix

Each option is enforced by a different mechanism per platform; an option
marked *ignored* is an honest no-op there.

| Option | Linux | macOS | Windows |
| --- | --- | --- | --- |
| `fs` | Landlock | Seatbelt profile | AppContainer + additive ACL grants |
| `network` | seccomp socket-family filter | Seatbelt network rules | AppContainer capabilities |
| `memoryLimitMb`, `cpuTimeLimitSecs`, `maxProcesses` | `setrlimit` — per-process caps, not tree-wide budgets; `maxProcesses` is `RLIMIT_NPROC`, counted per real UID and not enforced for privileged users | `setrlimit` — same per-process semantics as Linux | Job Object — aggregate budget for the whole process tree |
| `env` | cleared, then set | cleared, then set | cleared, then set |
| `linuxIpc` | seccomp (SysV/POSIX IPC, Unix sockets, ptrace) | ignored — IPC follows generated/imported Seatbelt rules; network grants can permit Unix-socket connections | ignored — AppContainer baseline isolation applies independently; see backend limits |
| `darwinSandboxProfiles` | ignored | trusted `.sb` policy imports that can grant access absent from `fs`/`network` | ignored |
| `windowsCacheNamespace` | ignored | ignored | AppContainer/ACL cache key |

On Windows there is no configurable IPC option, but AppContainer baseline
isolation still applies. Access to a securable object requires both the normal
user/group side and the package/capability side of the child's token; effective
access is their intersection and remains subject to integrity level and other
policy. Some system resources deliberately grant regular AppContainers access,
often through `ALL APPLICATION PACKAGES`, so they remain potentially reachable.
Children sharing one `windowsCacheNamespace` (and filesystem policy) share a
package SID and are not isolated from each other.

## API Notes

- The sandbox denies everything by default. Grant exactly the access the child
  needs.
- The sandbox fails closed: `Sandbox.build` throws when a capability probe
  fails, and spawning throws if confinement cannot actually be applied. A
  child is never run unconstrained as a fallback.
- Call `probeSupport()` to detect known incompatibilities up front. On Linux,
  it verifies Landlock enforcement on a disposable thread, but the seccomp
  check only queries whether the kernel reports the filter's `Trap` action.
  Ambient policy may still prevent filter installation, so a successful probe
  is not proof that spawning will succeed.
- Filesystem rules are applied in array order. Later matching rules override
  earlier matching rules for the same right.
- `stdio` is inherited from the parent process. Output capture is not yet
  supported.
- No other parent file descriptor or handle reaches the child: on Linux and
  macOS every descriptor above stderr is closed at exec, and on Windows handle
  inheritance is disabled. Policies cannot revoke access to already-open
  descriptors, so a long-lived host's sockets, pipes, and files must not leak
  into the sandbox.
- `cwd` is passed per spawn:

  ```js
  const child = sandbox.spawn('/usr/bin/mytool', ['--flag'], { cwd: workRoot })
  ```

- `child.kill()` is best-effort once `wait()` is in flight: it sends SIGKILL on
  Unix and is unsupported on Windows in that state.
- `linuxIpc` is Linux-only and ignored on macOS and Windows.
- `windowsCacheNamespace` is Windows-only and ignored on Linux and macOS.
- `darwinSandboxProfiles` is macOS-only and ignored on Linux and Windows. On
  macOS, imports are trusted policy that can grant access absent from `fs` and
  `network`.
