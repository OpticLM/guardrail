# Plan 007: Add Windows workspace target gates and a backend crate skeleton

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving on. If any
> STOP condition occurs, stop and report; do not improvise. When done, update
> the status row for this plan in `plans/README.md`.
>
> **Drift check (run first)**:
> `jj diff --from 44fcf4e0 -- Cargo.toml crates/guardrail-linux/Cargo.toml crates/guardrail-linux/src/lib.rs crates/guardrail-linux/tests crates/guardrail-core/src crates`
> If any in-scope file changed since this plan was written, compare the Current
> state excerpts below against the live code before proceeding.

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: MED (workspace and platform-gating changes affect every build)
- **Depends on**: plans/001
- **Category**: dx / migration
- **Planned at**: commit `44fcf4e0`, 2026-06-21

## Why this matters

The Windows backend cannot be added while the workspace itself fails on a
Windows target. On this host, `cargo test --workspace` currently fails inside
`seccompiler` because `guardrail-linux` is an unconditional workspace member and
pulls Linux-only `libc` seccomp APIs. This plan makes the Linux crate compile as
a harmless unsupported stub off Linux, gates Linux integration tests, and adds a
`guardrail-windows` crate skeleton that returns `Error::Unsupported` until the
real Job Object/AppContainer plans land.

## Current state

- `Cargo.toml:3` currently lists only `crates/guardrail-core` and
  `crates/guardrail-linux` as workspace members.
- `Cargo.toml:14-16` declares Linux-only dependencies (`libc`, `landlock`,
  `seccompiler`) as normal workspace dependencies.
- `crates/guardrail-linux/Cargo.toml:10-13` pulls those dependencies
  unconditionally.
- `crates/guardrail-linux/Cargo.toml` also declares the deterministic
  `guardrail-probe` test helper binary at `src/bin/guardrail-probe.rs`; that
  binary uses Linux-only `libc` APIs and must be target-gated alongside the
  Linux integration tests.
- `crates/guardrail-linux/src/lib.rs:9-17` imports
  `std::os::unix::process::CommandExt`, `libc`, Landlock, and seccomp modules
  without `cfg(target_os = "linux")`.
- `crates/guardrail-core/src/backend.rs:17-19` defines the backend seam:
  `fn spawn(&self, config: &SandboxConfig, command: Command) -> Result<SandboxChild, Error>;`.
- Verification baseline from recon:
  - `cargo test -p guardrail-core` exits 0 on Windows.
  - `cargo test --workspace` fails on Windows with unresolved Linux `libc`
    seccomp symbols in `seccompiler`.

## Commands you will need

| Purpose | Command | Expected on success |
|---------|---------|---------------------|
| Core baseline | `cargo test -p guardrail-core` | 5 unit tests + 1 doctest pass |
| Workspace on Windows | `cargo test --workspace` | exit 0 after Linux gating |
| Windows crate build | `cargo build -p guardrail-windows` | exit 0 |
| Linux crate non-Linux build | `cargo build -p guardrail-linux` | exit 0 with unsupported stub on Windows |
| Lint | `cargo clippy --workspace --all-targets -- -D warnings` | exit 0 |
| Format | `cargo fmt --check` | exit 0 |

## Scope

**In scope**:
- `Cargo.lock`
- `Cargo.toml`
- `crates/guardrail-linux/Cargo.toml`
- `crates/guardrail-linux/src/lib.rs`
- `crates/guardrail-linux/src/bin/guardrail-probe.rs`
- `crates/guardrail-linux/tests/*.rs`
- `crates/guardrail-windows/Cargo.toml` (create)
- `crates/guardrail-windows/src/lib.rs` (create)
- `plans/README.md`

**Out of scope**:
- Implementing Job Objects, AppContainer, ACL changes, or Windows process
  launch. Those are plans 008 and 009.
- Changing `guardrail-core` public API in this plan.
- Changing Linux confinement behavior on Linux.

## Version control

Repo uses **jj** colocated with git. Do not commit, branch, push, or run git
history-rewriting commands. Leave changes in the working copy.

## Steps

### Step 1: Add `guardrail-windows` to the workspace

Update root `Cargo.toml`:
- Add `"crates/guardrail-windows"` to `workspace.members`.
- Add `windows-sys = "0.61"` to `[workspace.dependencies]`, but do not use it
  until later plans.

Create `crates/guardrail-windows/Cargo.toml`:
- Package name: `guardrail-windows`.
- Description: `Windows backend for the guardrail sandbox (AppContainer + Job Objects).`
- Use workspace `version`, `edition`, `license`, `repository`.
- Dependency: `guardrail-core.workspace = true`.

Create `crates/guardrail-windows/src/lib.rs` with the same public shape as
`guardrail-linux`: a documented `WindowsBackend { _private: () }`, `new()`, and
an `impl Backend for WindowsBackend`. The `spawn` implementation must return:

```rust
Err(Error::Unsupported(
    "guardrail-windows confinement is not implemented yet; run plans 008-009".into(),
))
```

Do not spawn the child as a pass-through. A backend that silently runs without
confinement is worse than no backend.

**Verify**: `cargo build -p guardrail-windows` -> exit 0.

### Step 2: Gate `guardrail-linux` code on Linux

In `crates/guardrail-linux/Cargo.toml`, keep `guardrail-core` available for the
non-Linux stub and move only the Linux-only dependencies under a target table:

```toml
[dependencies]
guardrail-core.workspace = true

[target.'cfg(target_os = "linux")'.dependencies]
libc.workspace = true
landlock.workspace = true
seccompiler.workspace = true
```

In `crates/guardrail-linux/src/lib.rs`:
- Add `#[cfg(target_os = "linux")]` to the Unix imports, private modules, and
  Linux implementation.
- Add a non-Linux `LinuxBackend` stub with `new()` and `Backend::spawn(...)`
  returning `Error::Unsupported("guardrail-linux is only available on Linux".into())`.
- Preserve the Linux implementation exactly under `cfg(target_os = "linux")`.

In `crates/guardrail-linux/src/bin/guardrail-probe.rs`:
- Preserve the existing Linux helper behavior exactly under
  `#[cfg(target_os = "linux")]`.
- Add a non-Linux `main()` stub that prints a short unsupported message to
  stderr and exits with code `2` (usage/helper unavailable), without importing
  or referencing `libc`.
- Prefer a minimal split such as a Linux-only `linux_main()` containing the
  current body and a Linux `main()` that calls it, plus the non-Linux stub.

**Verify**: `cargo build -p guardrail-linux` -> exit 0 on Windows, without
compiling `seccompiler`.

### Step 3: Gate Linux integration tests

At the top of every file in `crates/guardrail-linux/tests/*.rs`, add:

```rust
#![cfg(target_os = "linux")]
```

Do not rewrite the test bodies. They are still the Linux intent tests and should
run unchanged on Linux.

**Verify**: `cargo test -p guardrail-linux` -> exit 0 on Windows with no Linux
integration tests run.

### Step 4: Run the workspace gates

Run:
- `cargo test -p guardrail-core` -> 5 unit tests and 1 doctest pass.
- `cargo test --workspace` -> exits 0 on Windows.
- `cargo clippy --workspace --all-targets -- -D warnings` -> exits 0.
- `cargo fmt --check` -> exits 0.

## Test plan

- Existing `guardrail-core` tests remain the behavioral baseline.
- `guardrail-linux` should compile and test as an unsupported stub on Windows;
  on Linux, its existing tests should still run because only `cfg` gates were
  added.
- `guardrail-windows` has no behavior tests yet because its backend deliberately
  returns `Unsupported`.

## Done criteria

- [ ] `cargo test --workspace` no longer fails on Windows due to
      `seccompiler`/Linux `libc` symbols.
- [ ] `cargo build -p guardrail-windows` exits 0.
- [ ] `guardrail-windows::WindowsBackend::new()` exists and `spawn` returns
      `Error::Unsupported`.
- [ ] Linux confinement code remains unchanged except for `cfg` gates.
- [ ] `guardrail-probe` keeps the same behavior on Linux and compiles as an
      unsupported helper stub on non-Linux targets without `libc`.
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` exits 0.
- [ ] `cargo fmt --check` exits 0.
- [ ] `plans/README.md` row 007 is updated to DONE.

## STOP conditions

Stop and report if:
- Making `guardrail-linux` compile on Windows requires deleting or changing
  Linux confinement logic instead of target-gating it.
- `cargo test --workspace` still tries to compile `seccompiler` on Windows after
  the target-specific dependency move.
- The Windows skeleton would need to spawn unconstrained child processes to make
  tests pass.

## Maintenance notes

The Linux crate remains a workspace member so `cargo test --workspace` checks
that the public package graph is coherent on every host. Its non-Linux stub is
not a feature; it exists only to keep cross-platform workspace commands usable.
Future platform crates should follow the same pattern: compile everywhere,
return `Unsupported` where the backend cannot enforce confinement.
