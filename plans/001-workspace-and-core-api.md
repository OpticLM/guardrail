# Plan 001: Convert the repo to a Cargo workspace and build the `guardrail-core` crate

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md`.
>
> **Drift check (run first)**: `git diff --stat a1d2a66..HEAD -- Cargo.toml src/lib.rs crates/`
> If `Cargo.toml` or `src/lib.rs` changed since this plan was written, compare
> the "Current state" excerpts against the live files before proceeding; on a
> mismatch, treat it as a STOP condition.

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: LOW
- **Depends on**: none (this is the foundation; plans 002–006 all depend on it)
- **Category**: direction (greenfield implementation of a designed API)
- **Planned at**: commit `a1d2a66`, 2026-06-21

## Why this matters

`guardrail` is a from-scratch sandbox library for running untrusted, LLM-generated
shell commands. `spec.md` describes a **declarative, builder-driven API** with
**platform-specific backends** (Linux, Windows, macOS). To keep platform code
isolated and the public surface portable, the project is split into a
platform-agnostic `guardrail-core` crate (types, builder, the `Backend` trait)
and per-platform crates (`guardrail-linux`, etc.) that implement `Backend`.

This plan creates the Cargo workspace and the **entire `guardrail-core` public
API**. Everything else in the project depends on these types being right, so the
goal here is a clean, well-tested, **platform-independent** crate that compiles
and tests on any OS. No Linux/kernel code appears here — that lands in plans
002–006.

## Current state

The repo is a default `cargo new --lib` skeleton. Two files matter:

`Cargo.toml` (the whole file):
```toml
[package]
name = "guardrail"
version = "0.1.0"
edition = "2024"

[dependencies]
```

`src/lib.rs` (the whole file):
```rust
pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
```

Both are placeholder content from `cargo new` and will be **removed/replaced**.

### Design constraints from `spec.md` (inlined — the executor has not read it)

- **§1 KISS / Default-Deny / Declarative / Stateless**: policies are data
  (enums); the default configuration denies everything (no FS, no network, no
  IPC, empty environment); side effects happen only at spawn time.
- **§3 API shape**: a `SandboxBuilder` using the builder pattern produces a
  configuration; spawning does an **unconditional** `env_clear()` + inject the
  builder's allow-listed env, then dispatches to a platform backend.
- **§5 policies** the API must express:
  - Filesystem: read-only grant for a path; read-write grant for a path; nothing
    readable/writable by default.
  - Network: deny by default; allow **outbound only** (bind/listen still
    denied); allow **bind/listen**. (A Windows-only "allow loopback" level
    exists in the spec but is a no-op elsewhere — model it but it has no effect
    on non-Windows.)
  - IPC: deny by default ("strict"); a "relaxed" level that permits benign
    mechanisms (pipes, `socketpair`, shared memory, anonymous mmap).
  - Resource limits: max memory, max CPU time, max child processes.
- **§6 Observability**: when a sandboxed program is killed/errors due to a
  policy violation, the library should be able to tell the caller which policy
  to add. (The *types* for this live in core; the Linux logic lands in plan
  006. This plan only needs to leave room for it — do **not** build diagnostics
  here.)

> **Note on the spec's example code**: `spec.md` §3 shows an illustrative
> `Policy` enum and `SandboxBuilder`. The spec explicitly says it is "not the
> final code ... rather than a rigid template to copy exactly." Implement the
> API **as specified in this plan**, which refines the spec into a cleaner shape.

### Decided architecture (follow exactly)

- **Virtual workspace** at the repo root. Members live under `crates/`. There is
  **no** root package anymore (the `guardrail` name is freed for a future
  facade crate; not in scope here).
- `guardrail-core` is **platform-agnostic** and has **no** OS-specific
  dependencies. It must compile on Linux, macOS, and Windows.
- The builder produces an immutable `SandboxConfig` (plain data with **public
  fields**, so a backend in a *different crate* can read it).
- A `Backend` trait abstracts platform confinement. `SandboxConfig::spawn_with`
  is the single entry point: it performs the **unconditional env scrub** in core
  (platform-agnostic, per §3), then delegates to the backend. This guarantees
  the env scrub happens regardless of which backend is used.

## Commands you will need

| Purpose          | Command                                                     | Expected on success      |
|------------------|-------------------------------------------------------------|--------------------------|
| Build core       | `cargo build -p guardrail-core`                             | exit 0                   |
| Test core        | `cargo test -p guardrail-core`                              | all tests pass           |
| Lint             | `cargo clippy -p guardrail-core --all-targets -- -D warnings` | exit 0, no warnings    |
| Format check     | `cargo fmt --check`                                         | exit 0                   |
| Docs build       | `cargo doc --no-deps -p guardrail-core`                     | exit 0                   |

Toolchain present: `rustc`/`cargo` 1.95, edition 2024. No network access is
needed to build except for the first dependency fetch (`thiserror`).

## Suggested executor toolkit

- The repo configures the **`docs-rs`** and **`context7`** MCP servers
  (`.mcp.json`). If a type/method name in this plan doesn't compile, look it up
  with `docs-rs` (`thiserror`) before guessing.

## Scope

**In scope** (create/modify only these):
- `Cargo.toml` (rewrite as a virtual workspace)
- `src/lib.rs` (delete — its `add()` placeholder is removed)
- `crates/guardrail-core/Cargo.toml` (create)
- `crates/guardrail-core/src/lib.rs` (create)
- `crates/guardrail-core/src/policy.rs` (create)
- `crates/guardrail-core/src/config.rs` (create)
- `crates/guardrail-core/src/builder.rs` (create)
- `crates/guardrail-core/src/backend.rs` (create)
- `crates/guardrail-core/src/process.rs` (create)
- `crates/guardrail-core/src/error.rs` (create)
- `plans/README.md` (status update only)

**Out of scope** (do NOT create or touch):
- Any `crates/guardrail-linux/**` — that is plan 002.
- Any Landlock / seccomp / `libc` / `setrlimit` / `pre_exec` code — later plans.
- Any `diagnostics`/`Violation` types — that is plan 006. Do not add them now.
- A facade `guardrail` crate — not in this project's current scope.

## Version control

This repo uses **jj (Jujutsu)** colocated with git. **Do not commit, branch, or
push.** Leave all changes in the working copy for the operator to review. (Drift
checks in this plan use `git diff`, which works read-only on the colocated repo.)

## Steps

### Step 1: Rewrite the root `Cargo.toml` as a virtual workspace and delete the placeholder lib

Replace the **entire** contents of `Cargo.toml` with:

```toml
[workspace]
resolver = "3"
members = ["crates/guardrail-core"]

[workspace.package]
version = "0.1.0"
edition = "2024"
license = "MIT OR Apache-2.0"
repository = "https://github.com/EFLKumo/guardrail"

[workspace.dependencies]
# Shared dependency versions. guardrail-linux (plan 002) adds landlock,
# seccompiler, and libc here; do not add those now.
thiserror = "2"
guardrail-core = { path = "crates/guardrail-core" }
```

Then **delete** `src/lib.rs` (and the now-empty `src/` directory if present).

> `members` lists only `guardrail-core` for now. Plan 002 appends
> `"crates/guardrail-linux"`.

**Verify**:
- `test ! -f src/lib.rs && echo "placeholder removed"` → prints `placeholder removed`
- `cargo metadata --no-deps --format-version 1 >/dev/null && echo ok` → prints `ok`
  (this fails loudly if the workspace manifest is malformed)

### Step 2: Create the `guardrail-core` crate manifest

Create `crates/guardrail-core/Cargo.toml`:

```toml
[package]
name = "guardrail-core"
description = "Core interfaces for the guardrail sandbox: policies, builder, and the platform Backend trait."
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true

[dependencies]
thiserror.workspace = true
```

**Verify**: `cargo build -p guardrail-core` → fails with "file not found for module"
or "main/lib not found" (expected — `src/lib.rs` does not exist yet; proceed to
Step 3). Do **not** treat this expected failure as a STOP condition.

### Step 3: Create `policy.rs` — the declarative policy enums

Create `crates/guardrail-core/src/policy.rs`:

```rust
//! Declarative sandbox policies.
//!
//! Policies are plain data. They describe *what is allowed*; everything not
//! granted is denied by default (see `spec.md` §1 "Default Deny").

use std::path::PathBuf;

/// A single filesystem grant. Everything beneath `path` is covered.
///
/// By default the sandbox grants no filesystem access at all. A backend may
/// additionally grant read+execute on standard system directories so the
/// target binary can actually be loaded and run (see plan 003); that is a
/// backend implementation detail, not part of this declarative model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsAccess {
    /// Grant read (and, for the contained binaries/libraries, execute) access
    /// to `path` and everything beneath it.
    Read(PathBuf),
    /// Grant read **and** write access to `path` and everything beneath it.
    Write(PathBuf),
}

/// Network confinement level. Default is [`NetworkPolicy::Deny`].
///
/// Mirrors `spec.md` §5.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NetworkPolicy {
    /// No network access of any kind.
    #[default]
    Deny,
    /// Outbound connections allowed; binding/listening still denied.
    OutboundOnly,
    /// Outbound connections **and** binding/listening allowed.
    Full,
}

/// Inter-process-communication confinement level. Default is
/// [`IpcPolicy::Strict`].
///
/// Mirrors `spec.md` §5.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IpcPolicy {
    /// Deny cross-process IPC: SysV shared memory / message queues /
    /// semaphores, POSIX message queues, and process inspection (`ptrace`,
    /// `process_vm_*`). Benign same-process primitives (pipes, `socketpair`,
    /// anonymous `mmap`) remain available.
    #[default]
    Strict,
    /// Like `Strict`, but additionally permit shared memory and POSIX message
    /// queues. Process inspection (`ptrace`, `process_vm_*`) stays denied.
    Relaxed,
}
```

**Verify**: (no standalone build yet — verified at Step 9.) Re-read the file and
confirm `NetworkPolicy` and `IpcPolicy` both derive `Default` with the
`#[default]` on `Deny`/`Strict` respectively.

### Step 4: Create `config.rs` — resource limits and the built configuration

Create `crates/guardrail-core/src/config.rs`:

```rust
//! The immutable, built sandbox configuration consumed by a [`Backend`].
//!
//! [`Backend`]: crate::Backend

use std::collections::BTreeMap;

use crate::backend::Backend;
use crate::error::Error;
use crate::policy::{FsAccess, IpcPolicy, NetworkPolicy};
use crate::process::SandboxChild;

/// Resource limits applied to the sandboxed process tree.
///
/// `None` means "do not impose this limit". Units are chosen to be unambiguous
/// at the API boundary; backends convert to the platform representation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResourceLimits {
    /// Maximum address space (virtual memory) in **bytes**.
    pub memory_bytes: Option<u64>,
    /// Maximum CPU time in **seconds**.
    pub cpu_time_secs: Option<u64>,
    /// Maximum number of processes/threads.
    pub max_processes: Option<u64>,
}

/// A fully-built, immutable sandbox configuration.
///
/// Produced by [`SandboxBuilder::build`](crate::SandboxBuilder::build). Fields
/// are public so platform backend crates can read them directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxConfig {
    /// Filesystem grants, in the order they were declared.
    pub fs: Vec<FsAccess>,
    /// Network confinement level.
    pub network: NetworkPolicy,
    /// IPC confinement level.
    pub ipc: IpcPolicy,
    /// Resource limits.
    pub limits: ResourceLimits,
    /// The **only** environment variables the child will see. The child's
    /// inherited environment is unconditionally cleared before these are
    /// applied (see [`SandboxConfig::spawn_with`]).
    pub env: BTreeMap<String, String>,
}

impl SandboxConfig {
    /// Spawn `command` under `backend`, applying this configuration.
    ///
    /// This performs the **unconditional security action** required by
    /// `spec.md` §3 — clearing every inherited environment variable and
    /// injecting only `self.env` — and then delegates platform confinement to
    /// the backend. Doing the scrub here guarantees it happens no matter which
    /// backend is used.
    pub fn spawn_with<B: Backend>(
        &self,
        backend: &B,
        mut command: std::process::Command,
    ) -> Result<SandboxChild, Error> {
        command.env_clear();
        command.envs(&self.env);
        backend.spawn(self, command)
    }
}
```

**Verify**: (built at Step 9.) Confirm `spawn_with` calls `env_clear()` **before**
`envs(&self.env)` — order matters.

### Step 5: Create `error.rs` — the public error type

Create `crates/guardrail-core/src/error.rs`:

```rust
//! The crate's error type.

/// Errors returned when configuring or spawning a sandbox.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The child process could not be spawned (e.g. binary not found).
    #[error("failed to spawn sandboxed process: {0}")]
    Spawn(#[from] std::io::Error),

    /// A platform confinement stage failed. `stage` is a short machine label
    /// such as `"landlock"`, `"seccomp"`, or `"rlimit"`.
    #[error("failed to apply {stage} confinement: {source}")]
    Confinement {
        stage: &'static str,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },

    /// A requested feature is not available on this platform or kernel.
    #[error("sandbox feature unsupported here: {0}")]
    Unsupported(String),
}

impl Error {
    /// Convenience constructor for [`Error::Confinement`].
    pub fn confinement<E>(stage: &'static str, source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Error::Confinement {
            stage,
            source: Box::new(source),
        }
    }
}
```

> `#[non_exhaustive]` lets later plans add variants without a breaking change.
> The `Confinement` variant lets the Linux crate wrap `landlock`/`seccomp`
> errors without `guardrail-core` depending on those crates.

### Step 6: Create `process.rs` — the spawned-process handle

Create `crates/guardrail-core/src/process.rs`:

```rust
//! Handle to a running sandboxed process.

use std::process::{Child, ExitStatus};

/// A handle to a spawned, sandboxed child process.
///
/// Thin wrapper around [`std::process::Child`]. Backends construct it with
/// `SandboxChild::from`. Observability helpers (plan 006) will consume the exit
/// status alongside the [`SandboxConfig`](crate::SandboxConfig) that produced
/// the child.
#[derive(Debug)]
pub struct SandboxChild {
    inner: Child,
}

impl SandboxChild {
    /// The OS-assigned process id of the child.
    pub fn id(&self) -> u32 {
        self.inner.id()
    }

    /// Wait for the child to exit, returning its status.
    pub fn wait(&mut self) -> std::io::Result<ExitStatus> {
        self.inner.wait()
    }

    /// Attempt to kill the child immediately.
    pub fn kill(&mut self) -> std::io::Result<()> {
        self.inner.kill()
    }

    /// Borrow the underlying [`Child`] (e.g. to take its stdio handles).
    pub fn inner_mut(&mut self) -> &mut Child {
        &mut self.inner
    }

    /// Consume the handle and return the underlying [`Child`].
    pub fn into_inner(self) -> Child {
        self.inner
    }
}

impl From<Child> for SandboxChild {
    fn from(inner: Child) -> Self {
        SandboxChild { inner }
    }
}
```

### Step 7: Create `backend.rs` — the platform backend trait

Create `crates/guardrail-core/src/backend.rs`:

```rust
//! The platform-confinement abstraction.

use std::process::Command;

use crate::config::SandboxConfig;
use crate::error::Error;
use crate::process::SandboxChild;

/// A platform-specific sandbox backend.
///
/// Implementors apply OS-level confinement (filesystem, network, IPC, resource
/// limits) and spawn the child. The `command` they receive has **already** had
/// its environment scrubbed by [`SandboxConfig::spawn_with`] — a backend must
/// not re-add inherited environment variables.
///
/// The trait is object-safe so callers may hold a `&dyn Backend` if they wish.
pub trait Backend {
    /// Spawn `command` confined according to `config`.
    fn spawn(&self, config: &SandboxConfig, command: Command) -> Result<SandboxChild, Error>;
}
```

### Step 8: Create `builder.rs` — the public builder

Create `crates/guardrail-core/src/builder.rs`:

```rust
//! The [`SandboxBuilder`] — the primary entry point for callers.

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::config::{ResourceLimits, SandboxConfig};
use crate::policy::{FsAccess, IpcPolicy, NetworkPolicy};

/// Builds a [`SandboxConfig`] using the builder pattern.
///
/// All methods take and return `self` by value for chaining. The default
/// configuration is maximally restrictive (`spec.md` §1 "Default Deny"): no
/// filesystem access, no network, strict IPC, no resource limits, and an empty
/// environment.
///
/// # Example
/// ```
/// use guardrail_core::{SandboxBuilder, NetworkPolicy};
///
/// let config = SandboxBuilder::new()
///     .allow_read("/usr")
///     .allow_write("/tmp/work")
///     .network(NetworkPolicy::OutboundOnly)
///     .memory_limit_mb(256)
///     .env("PATH", "/usr/bin:/bin")
///     .build();
/// assert_eq!(config.network, NetworkPolicy::OutboundOnly);
/// ```
#[derive(Debug, Clone, Default)]
pub struct SandboxBuilder {
    fs: Vec<FsAccess>,
    network: NetworkPolicy,
    ipc: IpcPolicy,
    limits: ResourceLimits,
    env: BTreeMap<String, String>,
}

impl SandboxBuilder {
    /// Start from the default (maximally restrictive) configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Grant read (and execute) access to `path` and everything beneath it.
    pub fn allow_read(mut self, path: impl Into<PathBuf>) -> Self {
        self.fs.push(FsAccess::Read(path.into()));
        self
    }

    /// Grant read+write access to `path` and everything beneath it.
    pub fn allow_write(mut self, path: impl Into<PathBuf>) -> Self {
        self.fs.push(FsAccess::Write(path.into()));
        self
    }

    /// Set the network confinement level (last call wins).
    pub fn network(mut self, policy: NetworkPolicy) -> Self {
        self.network = policy;
        self
    }

    /// Set the IPC confinement level (last call wins).
    pub fn ipc(mut self, policy: IpcPolicy) -> Self {
        self.ipc = policy;
        self
    }

    /// Limit address space (virtual memory) to `mb` megabytes.
    pub fn memory_limit_mb(mut self, mb: u64) -> Self {
        self.limits.memory_bytes = Some(mb.saturating_mul(1024 * 1024));
        self
    }

    /// Limit CPU time to `secs` seconds.
    pub fn cpu_time_limit_secs(mut self, secs: u64) -> Self {
        self.limits.cpu_time_secs = Some(secs);
        self
    }

    /// Limit the number of processes/threads.
    pub fn max_processes(mut self, n: u64) -> Self {
        self.limits.max_processes = Some(n);
        self
    }

    /// Add one environment variable to the (otherwise empty) child environment.
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(key.into(), value.into());
        self
    }

    /// Add several environment variables at once.
    pub fn envs<I, K, V>(mut self, vars: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        for (k, v) in vars {
            self.env.insert(k.into(), v.into());
        }
        self
    }

    /// Finalize into an immutable [`SandboxConfig`].
    pub fn build(self) -> SandboxConfig {
        SandboxConfig {
            fs: self.fs,
            network: self.network,
            ipc: self.ipc,
            limits: self.limits,
            env: self.env,
        }
    }
}
```

### Step 9: Create `lib.rs` — wire the modules and re-export the public API

Create `crates/guardrail-core/src/lib.rs`:

```rust
//! Core interfaces for the `guardrail` sandbox.
//!
//! This crate is platform-agnostic: it defines the declarative [`policy`]
//! types, the [`SandboxBuilder`], the built [`SandboxConfig`], and the
//! [`Backend`] trait that platform crates (e.g. `guardrail-linux`) implement.
//! It contains no OS-specific code and compiles on every platform.
//!
//! See `spec.md` for the full design.

mod backend;
mod builder;
mod config;
mod error;
mod policy;
mod process;

pub use backend::Backend;
pub use builder::SandboxBuilder;
pub use config::{ResourceLimits, SandboxConfig};
pub use error::Error;
pub use policy::{FsAccess, IpcPolicy, NetworkPolicy};
pub use process::SandboxChild;
```

**Verify**:
- `cargo build -p guardrail-core` → exit 0
- `cargo doc --no-deps -p guardrail-core` → exit 0 (the doctest example compiles)

### Step 10: Add unit tests that validate intent (not implementation)

Per `spec.md` §7, tests must assert the **high-level intent**, not re-trace the
code. Add a `#[cfg(test)] mod tests` block **at the end of
`crates/guardrail-core/src/builder.rs`** and a small backend test in
`crates/guardrail-core/src/backend.rs`. Write these specific cases:

In `builder.rs` tests:
1. `default_config_denies_everything`: `SandboxBuilder::new().build()` yields
   `network == NetworkPolicy::Deny`, `ipc == IpcPolicy::Strict`, empty `fs`,
   empty `env`, and a `ResourceLimits` with all fields `None`. (Intent: the
   default is maximally restrictive.)
2. `memory_limit_is_expressed_in_bytes`: `.memory_limit_mb(2)` produces
   `limits.memory_bytes == Some(2 * 1024 * 1024)`. (Intent: the MB→bytes
   contract at the boundary.)
3. `fs_grants_preserve_declaration_order`: declaring `.allow_read("/a")` then
   `.allow_write("/b")` yields `fs == [FsAccess::Read("/a"), FsAccess::Write("/b")]`.
4. `last_network_call_wins`: `.network(Full).network(Deny)` ends `Deny`.

In `backend.rs` tests:
5. `spawn_with_scrubs_then_delegates`: define a `RecordingBackend` implementing
   `Backend` whose `spawn` records the received `SandboxConfig` (clone it into a
   `RefCell`/`Mutex`) and returns an `Err(Error::Unsupported(...))` (so no real
   process is created). Build a config with one env var, call
   `config.spawn_with(&backend, Command::new("true"))`, and assert the backend
   received a `SandboxConfig` equal to the one built. (Intent: `spawn_with`
   delegates the *config* to the backend. The env-scrub *behavior* is verified
   end-to-end in plan 002 with a real process, because `std::process::Command`
   does not expose its environment for inspection.)

Use this structural pattern for the recording backend (adapt as needed):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::SandboxBuilder;
    use std::sync::Mutex;

    struct RecordingBackend {
        seen: Mutex<Option<SandboxConfig>>,
    }

    impl Backend for RecordingBackend {
        fn spawn(
            &self,
            config: &SandboxConfig,
            _command: std::process::Command,
        ) -> Result<SandboxChild, Error> {
            *self.seen.lock().unwrap() = Some(config.clone());
            Err(Error::Unsupported("recording backend never spawns".into()))
        }
    }

    #[test]
    fn spawn_with_scrubs_then_delegates() {
        let backend = RecordingBackend { seen: Mutex::new(None) };
        let config = SandboxBuilder::new().env("FOO", "bar").build();
        let _ = config.spawn_with(&backend, std::process::Command::new("true"));
        assert_eq!(backend.seen.lock().unwrap().as_ref(), Some(&config));
    }
}
```

**Verify**:
- `cargo test -p guardrail-core` → all 5 tests pass
- `cargo clippy -p guardrail-core --all-targets -- -D warnings` → exit 0
- `cargo fmt --check` → exit 0

## Test plan

- All tests live alongside the code they test (`builder.rs`, `backend.rs`), the
  conventional Rust unit-test location. There is no prior test to model after
  (greenfield); the patterns above are the template later plans will follow.
- The 5 cases above cover: the default-deny contract, the unit conversion, order
  preservation, last-wins semantics, and backend delegation.
- Run: `cargo test -p guardrail-core` → all pass (5 new tests).

## Done criteria

Machine-checkable. ALL must hold:

- [ ] `cargo metadata --no-deps --format-version 1 >/dev/null` exits 0 (valid workspace)
- [ ] `test ! -f src/lib.rs` (placeholder lib removed)
- [ ] `cargo build -p guardrail-core` exits 0
- [ ] `cargo test -p guardrail-core` exits 0 with 5 passing tests
- [ ] `cargo doc --no-deps -p guardrail-core` exits 0 (doctest compiles)
- [ ] `cargo clippy -p guardrail-core --all-targets -- -D warnings` exits 0
- [ ] `cargo fmt --check` exits 0
- [ ] No files outside the in-scope list are modified (`git status`)
- [ ] `plans/README.md` status row for 001 set to DONE

## STOP conditions

Stop and report back (do not improvise) if:

- The `Cargo.toml` or `src/lib.rs` on disk does not match the "Current state"
  excerpts (the repo drifted since this plan was written).
- `resolver = "3"` is rejected by the installed Cargo (it requires Cargo ≥1.84;
  recon recorded 1.95, so this should not happen). If it does, report the Cargo
  version — do not silently downgrade the resolver.
- `thiserror = "2"` cannot be fetched (offline). Report rather than pinning a
  different major version.
- You find yourself needing a Linux/`libc`/Landlock/seccomp symbol to make this
  compile — that means scope has leaked; stop. `guardrail-core` must build with
  zero OS-specific dependencies.

## Maintenance notes

- **For plan 002**: append `"crates/guardrail-linux"` to the workspace `members`
  and add `landlock`, `seccompiler`, `libc` to `[workspace.dependencies]`.
- **For plan 006**: a new `diagnostics` module will be added to this crate
  holding `Violation`/`ViolationKind` types. `SandboxConfig` and `SandboxChild`
  already carry enough for the caller to pair an exit status with the config; do
  not pre-build that here.
- A reviewer should confirm `SandboxConfig` fields are `pub` (cross-crate
  consumption depends on it) and that `Backend` stayed object-safe (no generic
  methods, no `Self`-returning methods).
- The public env contract (clear-all-then-inject) is load-bearing for security;
  any change to `spawn_with` must preserve the `env_clear()`-before-`envs()`
  ordering.
</content>
</invoke>
