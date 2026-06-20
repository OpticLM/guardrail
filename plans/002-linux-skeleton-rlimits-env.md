# Plan 002: Create `guardrail-linux` with the spawn scaffold, resource limits, and env scrubbing

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving on. If
> anything in "STOP conditions" occurs, stop and report — do not improvise.
> When done, update the status row for this plan in `plans/README.md`.
>
> **Drift check (run first)**: `git diff --stat <SHA-from-Status>..HEAD -- Cargo.toml crates/guardrail-core/`
> This plan assumes the `guardrail-core` API from plan 001 exists exactly as
> shipped. If `crates/guardrail-core/src/*` changed the names/shapes quoted in
> "Current state", reconcile before proceeding; on a real mismatch, STOP.

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: MED (introduces `unsafe` `pre_exec` and raw `libc` calls)
- **Depends on**: plans/001 (the `guardrail-core` crate must exist and build)
- **Category**: direction (greenfield implementation)
- **Planned at**: commit `a1d2a66`, 2026-06-21 (written against the plan-001 design; re-run the drift check)

## Why this matters

This plan stands up the **Linux backend crate** and the machinery every later
Linux plan builds on: the `LinuxBackend` type implementing `guardrail_core::Backend`,
the single `Command::pre_exec` hook where all in-process confinement is applied,
and a `guardrail-probe` helper binary that makes the integration tests
deterministic. It also delivers two real confinement features that need none of
Landlock/seccomp: **resource limits** via `setrlimit` (`spec.md` §4.1) and the
**environment scrub** (verified end-to-end here, since core can only check the
config-level contract).

After this plan, `LinuxBackend` spawns a process with memory/CPU/process-count
caps and a clean environment — but **not yet** filesystem, network, or IPC
confinement (plans 003/004/005 fill those into the same `pre_exec` hook).

## Current state

`guardrail-core` (from plan 001) exposes — quoting the shipped API you depend on:

- `guardrail_core::Backend` — `fn spawn(&self, config: &SandboxConfig, command: Command) -> Result<SandboxChild, Error>`
- `guardrail_core::SandboxConfig` — public fields:
  `fs: Vec<FsAccess>`, `network: NetworkPolicy`, `ipc: IpcPolicy`,
  `limits: ResourceLimits`, `env: BTreeMap<String, String>`
- `guardrail_core::ResourceLimits` — `memory_bytes: Option<u64>`,
  `cpu_time_secs: Option<u64>`, `max_processes: Option<u64>`
- `guardrail_core::Error` — variants `Spawn(io::Error)`,
  `Confinement { stage: &'static str, source: Box<dyn Error + Send + Sync> }`,
  `Unsupported(String)`; plus `Error::confinement(stage, source)` constructor.
- `guardrail_core::SandboxChild` — `impl From<std::process::Child>` (so the
  backend builds one from a `Child`).
- Env scrub already happens in `SandboxConfig::spawn_with` (core), **before**
  the backend's `spawn` runs. The backend must **not** re-add environment vars.

Workspace root `Cargo.toml` currently has `members = ["crates/guardrail-core"]`
and a `[workspace.dependencies]` table with `thiserror` and `guardrail-core`.

### Design facts you must honor (from `spec.md` and the plan-001 decisions)

- **All confinement is applied in-process via `Command::pre_exec`** — no
  `bwrap`, no external binary, no namespaces. (Decision recorded for this
  project: pure in-process Landlock + seccomp + `setrlimit`.)
- **`pre_exec` runs in the forked child between `fork` and `execvp`.** Its
  closure must avoid heap churn and non-async-signal-safe work where reasonable.
  `setrlimit`/`prctl` are thin syscall wrappers and are fine. (Landlock/seccomp
  in later plans allocate; that is the established practice of comparable crates
  — out of scope to re-engineer here.)
- **Set `PR_SET_NO_NEW_PRIVS=1` first** in `pre_exec`. It is required for
  seccomp without `CAP_SYS_ADMIN` (plans 004/005), is set anyway by Landlock,
  and independently hardens the sandbox (a setuid target cannot gain privileges).
  Establishing it now means later plans don't have to.
- **Resource-limit mapping** (`setrlimit(2)`):
  - `memory_bytes` → `RLIMIT_AS` (address space). Set soft = hard = value.
  - `cpu_time_secs` → `RLIMIT_CPU` (seconds). Soft limit raises `SIGXCPU`; hard
    limit raises `SIGKILL`. Set soft = hard = value.
  - `max_processes` → `RLIMIT_NPROC`. **Caveat**: `RLIMIT_NPROC` counts
    processes for the *real user id* across the whole system, not just this
    child's descendants — so it is best-effort and can interact with other
    processes the user runs. Implement it, but its test is `#[ignore]`d (see
    Test plan).

## Commands you will need

| Purpose            | Command                                                              | Expected on success     |
|--------------------|----------------------------------------------------------------------|-------------------------|
| Build linux crate  | `cargo build -p guardrail-linux`                                     | exit 0                  |
| Build probe binary | `cargo build -p guardrail-linux --bin guardrail-probe`               | exit 0                  |
| Test linux crate   | `cargo test -p guardrail-linux`                                      | all pass                |
| Run ignored tests  | `cargo test -p guardrail-linux -- --ignored`                         | (manual; may be flaky)  |
| Lint               | `cargo clippy -p guardrail-linux --all-targets -- -D warnings`       | exit 0                  |
| Format check       | `cargo fmt --check`                                                   | exit 0                  |

This host's kernel is `7.0.8` (modern; Landlock and seccomp both available), so
local tests should run for real.

## Suggested executor toolkit

- Use the **`docs-rs` MCP** to confirm `libc` constant/function names
  (`RLIMIT_AS`, `RLIMIT_CPU`, `RLIMIT_NPROC`, `rlimit`, `setrlimit`,
  `PR_SET_NO_NEW_PRIVS`, `prctl`) if anything fails to compile.
- `std::os::unix::process::CommandExt::pre_exec` and
  `std::os::unix::process::ExitStatusExt` are the relevant std APIs.

## Scope

**In scope** (create/modify only these):
- `Cargo.toml` (root) — add the new member and shared deps
- `crates/guardrail-linux/Cargo.toml` (create)
- `crates/guardrail-linux/src/lib.rs` (create — `LinuxBackend` + `spawn`)
- `crates/guardrail-linux/src/rlimit.rs` (create — `setrlimit` helpers)
- `crates/guardrail-linux/src/bin/guardrail-probe.rs` (create — test helper)
- `crates/guardrail-linux/tests/resource_limits.rs` (create — integration tests)
- `crates/guardrail-linux/tests/environment.rs` (create — env-scrub test)
- `plans/README.md` (status update)

**Out of scope** (do NOT touch / add):
- Any Landlock code or the `landlock` dependency — plan 003.
- Any seccomp code or the `seccompiler` dependency — plans 004/005.
- `guardrail-core` — its API is fixed by plan 001. If you think you need to
  change it, that is a STOP condition.
- A `mod fs;` or `mod seccomp;` — later plans create those. Leave a single
  documented insertion point in `pre_exec` (see Step 4) but no stubs.

## Version control

Repo uses **jj (Jujutsu)** colocated with git. **Do not commit/branch/push.**
Leave changes in the working copy for review.

## Steps

### Step 1: Register the crate and dependencies in the workspace

In the root `Cargo.toml`:
- Append `"crates/guardrail-linux"` to `members`.
- Add to `[workspace.dependencies]`:
  ```toml
  libc = "0.2"
  ```
  (Do **not** add `landlock`/`seccompiler` — later plans add those.)

**Verify**: `cargo metadata --no-deps --format-version 1 >/dev/null && echo ok`
→ prints `ok` (will still pass even though the crate dir is empty; the next step
adds the manifest). If it errors that the member path doesn't exist, proceed to
Step 2 then re-run.

### Step 2: Create the `guardrail-linux` crate manifest

Create `crates/guardrail-linux/Cargo.toml`:

```toml
[package]
name = "guardrail-linux"
description = "Linux backend for the guardrail sandbox (Landlock + seccomp + setrlimit)."
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true

[dependencies]
guardrail-core.workspace = true
libc.workspace = true

[dev-dependencies]
tempfile = "3"

# The deterministic integration-test helper. Tests locate it via the
# CARGO_BIN_EXE_guardrail-probe environment variable that Cargo sets for them.
[[bin]]
name = "guardrail-probe"
path = "src/bin/guardrail-probe.rs"
```

### Step 3: Implement `setrlimit` helpers in `rlimit.rs`

Create `crates/guardrail-linux/src/rlimit.rs`:

```rust
//! Resource limits via `setrlimit(2)`. Applied inside `pre_exec`, so every
//! function here must be async-signal-safe (only raw `libc` calls, no
//! allocation, no panics that unwind across the FFI boundary).

use std::io;

use guardrail_core::ResourceLimits;

/// Apply `limits` to the current process. Called from within `pre_exec` in the
/// freshly-forked child, before `execvp`.
///
/// Returns the first `errno`-based error encountered. `None` fields are skipped.
pub(crate) fn apply(limits: &ResourceLimits) -> io::Result<()> {
    if let Some(bytes) = limits.memory_bytes {
        set_one(libc::RLIMIT_AS, bytes)?;
    }
    if let Some(secs) = limits.cpu_time_secs {
        set_one(libc::RLIMIT_CPU, secs)?;
    }
    if let Some(n) = limits.max_processes {
        set_one(libc::RLIMIT_NPROC, n)?;
    }
    Ok(())
}

/// Set soft = hard = `value` for one resource.
fn set_one(resource: libc::__rlimit_resource_t, value: u64) -> io::Result<()> {
    let rl = libc::rlimit {
        rlim_cur: value as libc::rlim_t,
        rlim_max: value as libc::rlim_t,
    };
    // SAFETY: `rl` is a valid, fully-initialized rlimit for the duration of the
    // call; `setrlimit` does not retain the pointer.
    let rc = unsafe { libc::setrlimit(resource, &rl) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
```

> If `libc::RLIMIT_AS` has type `libc::__rlimit_resource_t` on this target the
> signature above compiles as-is; on some targets the constants are plain
> `c_int`. If the type doesn't match, check the exact type with the `docs-rs`
> MCP (`libc::setrlimit`) and adjust `set_one`'s parameter type — do not cast
> away a type error blindly.

**Verify**: deferred to Step 5 (the crate has no `lib.rs` yet).

### Step 4: Implement `LinuxBackend` and the `pre_exec` hook in `lib.rs`

Create `crates/guardrail-linux/src/lib.rs`:

```rust
//! Linux backend for `guardrail`.
//!
//! Applies confinement entirely in-process inside [`std::process::Command`]'s
//! `pre_exec` hook: resource limits via `setrlimit`, plus (in later plans)
//! Landlock filesystem rules and a seccomp-BPF filter for network and IPC. No
//! external sandboxing binary is used.

use std::os::unix::process::CommandExt;
use std::process::Command;

use guardrail_core::{Backend, Error, SandboxChild, SandboxConfig};

mod rlimit;

/// The Linux sandbox backend.
#[derive(Debug, Default, Clone)]
pub struct LinuxBackend {
    _private: (),
}

impl LinuxBackend {
    /// Create a new Linux backend.
    pub fn new() -> Self {
        Self::default()
    }
}

impl Backend for LinuxBackend {
    fn spawn(&self, config: &SandboxConfig, mut command: Command) -> Result<SandboxChild, Error> {
        // Clone only the data the child closure needs. The closure runs in the
        // forked child, so it must own its inputs (no borrows of `config`).
        let limits = config.limits;

        // SAFETY: the closure runs after fork() and before execvp() in the
        // child. It performs only async-signal-safe syscalls (prctl, setrlimit)
        // and returns an io::Error instead of panicking.
        unsafe {
            command.pre_exec(move || {
                // (1) NO_NEW_PRIVS first: required for seccomp later, and a
                //     hardening measure on its own. prctl is async-signal-safe.
                set_no_new_privs()?;

                // (2) Resource limits.
                rlimit::apply(&limits)?;

                // (3) INSERTION POINT — later plans add, in this order:
                //       fs::apply(&fs_rules)?;        // plan 003 (Landlock)
                //       seccomp::apply(&filter)?;     // plans 004/005 (last)
                //     Apply seccomp LAST so its filter does not interfere with
                //     Landlock's own setup syscalls.

                Ok(())
            });
        }

        let child = command.spawn().map_err(Error::Spawn)?;
        Ok(SandboxChild::from(child))
    }
}

/// `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)`. Async-signal-safe.
fn set_no_new_privs() -> std::io::Result<()> {
    // SAFETY: prctl with PR_SET_NO_NEW_PRIVS takes scalar args only.
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
```

> **Why clone `limits` into the closure**: `pre_exec`'s closure is `'static` +
> `Send` and runs post-fork; it cannot borrow `config`. `ResourceLimits` is
> `Copy`, so `let limits = config.limits;` is enough. Later plans that need
> `config.fs` / `config.network` / `config.ipc` will likewise clone what they
> need *before* the `unsafe` block.

**Verify**:
- `cargo build -p guardrail-linux` → exit 0
- `cargo clippy -p guardrail-linux --lib -- -D warnings` → exit 0

### Step 5: Create the `guardrail-probe` helper binary

This binary is the deterministic target for **all** Linux integration tests
(this plan and 003–006). It performs one requested operation and exits with a
documented code, so tests assert on behavior, not on the sandbox internals.

Create `crates/guardrail-linux/src/bin/guardrail-probe.rs`:

```rust
//! Test helper exercised by guardrail-linux integration tests.
//!
//! Usage: `guardrail-probe <COMMAND> [ARG]`
//!
//! Exit codes:
//!   0   operation succeeded / allowed
//!   3   operation failed because it was denied (the expected sandboxed result)
//!   2   usage error / unknown command
//!
//! Commands (this plan):
//!   echo-env <NAME>   print the value of env var NAME (empty if unset), exit 0
//!   alloc <MB>        try to allocate and touch <MB> megabytes; exit 0 if it
//!                     succeeds, exit 3 if allocation fails
//!   spin              busy-loop forever (for CPU-time-limit tests)
//!
//! Later plans add more commands (read-file, write-file, socket-inet, bind,
//! shm, ptrace, ...). Keep the dispatch table and exit-code contract stable.

use std::process::exit;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("");
    match cmd {
        "echo-env" => {
            let name = args.get(2).map(String::as_str).unwrap_or("");
            print!("{}", std::env::var(name).unwrap_or_default());
            exit(0);
        }
        "alloc" => {
            let mb: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
            // Allocate and touch every page so the kernel actually commits it.
            let mut v: Vec<u8> = Vec::new();
            if v.try_reserve(mb * 1024 * 1024).is_err() {
                exit(3);
            }
            v.resize(mb * 1024 * 1024, 0);
            let mut acc: u8 = 0;
            let mut i = 0;
            while i < v.len() {
                v[i] = 1;
                acc = acc.wrapping_add(v[i]);
                i += 4096;
            }
            // Use `acc` so the loop isn't optimized away.
            if acc == 123 {
                eprintln!("unreachable {acc}");
            }
            exit(0);
        }
        "spin" => loop {
            std::hint::spin_loop();
        },
        _ => {
            eprintln!("usage: guardrail-probe <echo-env|alloc|spin> [arg]");
            exit(2);
        }
    }
}
```

**Verify**: `cargo build -p guardrail-linux --bin guardrail-probe` → exit 0.

### Step 6: Integration test — environment scrubbing (end-to-end)

Create `crates/guardrail-linux/tests/environment.rs`:

```rust
//! Verifies the §3 "unconditional env scrub": the child sees ONLY the env vars
//! added to the builder, never the parent's inherited ones.

use std::process::Command;

use guardrail_core::SandboxBuilder;
use guardrail_linux::LinuxBackend;

fn probe() -> Command {
    Command::new(env!("CARGO_BIN_EXE_guardrail-probe"))
}

#[test]
fn inherited_env_is_cleared() {
    // A variable set in the parent must NOT reach the child.
    // SAFETY: single-threaded test setup before any spawn.
    unsafe { std::env::set_var("GUARDRAIL_SECRET", "leaked") };

    let config = SandboxBuilder::new().build();
    let mut cmd = probe();
    cmd.arg("echo-env").arg("GUARDRAIL_SECRET");
    cmd.stdout(std::process::Stdio::piped());

    let child = config.spawn_with(&LinuxBackend::new(), cmd).expect("spawn");
    let out = child.into_inner().wait_with_output().expect("wait");
    assert!(out.status.success());
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "",
        "inherited env var must not reach the sandboxed child"
    );
}

#[test]
fn explicitly_added_env_reaches_child() {
    let config = SandboxBuilder::new().env("GREETING", "hello").build();
    let mut cmd = probe();
    cmd.arg("echo-env").arg("GREETING");
    cmd.stdout(std::process::Stdio::piped());

    let child = config.spawn_with(&LinuxBackend::new(), cmd).expect("spawn");
    let out = child.into_inner().wait_with_output().expect("wait");
    assert_eq!(String::from_utf8_lossy(&out.stdout), "hello");
}
```

**Verify**: `cargo test -p guardrail-linux --test environment` → both pass.

### Step 7: Integration test — resource limits

Create `crates/guardrail-linux/tests/resource_limits.rs`:

```rust
//! Verifies that resource limits actually constrain the child (intent-level,
//! per spec §7): with a small memory cap a large allocation fails; with a CPU
//! cap a busy loop is killed within a bounded time.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use guardrail_core::SandboxBuilder;
use guardrail_linux::LinuxBackend;

fn probe() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_guardrail-probe"));
    c.stdout(Stdio::null()).stderr(Stdio::null());
    c
}

#[test]
fn memory_limit_blocks_large_allocation() {
    // 64 MiB address-space cap; ask the child to grab 512 MiB.
    let config = SandboxBuilder::new().memory_limit_mb(64).build();
    let mut cmd = probe();
    cmd.arg("alloc").arg("512");
    let mut child = config.spawn_with(&LinuxBackend::new(), cmd).expect("spawn");
    let status = child.wait().expect("wait");
    assert!(
        !status.success(),
        "allocation of 512 MiB must fail under a 64 MiB RLIMIT_AS"
    );
}

#[test]
fn without_limit_the_same_allocation_succeeds() {
    // Control: no cap → the 512 MiB allocation succeeds. Guards against the
    // probe being broken in a way that makes the test above pass spuriously.
    let config = SandboxBuilder::new().build();
    let mut cmd = probe();
    cmd.arg("alloc").arg("512");
    let mut child = config.spawn_with(&LinuxBackend::new(), cmd).expect("spawn");
    let status = child.wait().expect("wait");
    assert!(status.success(), "512 MiB should allocate when unconstrained");
}

#[test]
fn cpu_time_limit_kills_busy_loop() {
    // 1s CPU cap on an infinite spin. RLIMIT_CPU soft→SIGXCPU, hard→SIGKILL.
    let config = SandboxBuilder::new().cpu_time_limit_secs(1).build();
    let mut cmd = probe();
    cmd.arg("spin");
    let mut child = config.spawn_with(&LinuxBackend::new(), cmd).expect("spawn");

    let start = Instant::now();
    let status = child.wait().expect("wait");
    let elapsed = start.elapsed();

    assert!(!status.success(), "spinner must be killed, not exit cleanly");
    assert!(
        elapsed < Duration::from_secs(10),
        "spinner should die from the CPU limit well under 10s (took {elapsed:?})"
    );
}

#[test]
#[ignore = "RLIMIT_NPROC counts processes per real-uid system-wide; flaky in shared/CI environments"]
fn process_limit_is_applied() {
    // Best-effort: with max_processes(1) the child cannot fork a helper.
    // Left ignored because RLIMIT_NPROC depends on the ambient process count of
    // the running user. Run manually with `--ignored` on a quiet machine.
    let config = SandboxBuilder::new().max_processes(1).build();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_guardrail-probe"));
    cmd.arg("spin");
    let res = config.spawn_with(&LinuxBackend::new(), cmd);
    // The assertion is intentionally loose; document-only.
    let _ = res;
}
```

**Verify**:
- `cargo test -p guardrail-linux --test resource_limits` → 3 pass, 1 ignored
- `cargo test -p guardrail-linux` → all pass (env + resource tests), 1 ignored

## Test plan

- **environment.rs**: inherited var is cleared; explicitly-added var arrives.
  Covers the §3 unconditional scrub — the part core couldn't verify.
- **resource_limits.rs**: memory cap blocks a large alloc; the *same* alloc
  succeeds uncapped (control against a broken probe); CPU cap kills a spinner
  within a bounded wall-clock; nproc test present but `#[ignore]`d with reason.
- All tests use the `guardrail-probe` binary via `env!("CARGO_BIN_EXE_guardrail-probe")`
  — deterministic, no reliance on system tools or network.
- These are the structural template for the integration tests in plans 003–006.

## Done criteria

Machine-checkable. ALL must hold:

- [ ] `cargo build -p guardrail-linux` exits 0
- [ ] `cargo build -p guardrail-linux --bin guardrail-probe` exits 0
- [ ] `cargo test -p guardrail-linux` exits 0; environment (2) and
      resource_limits (3) tests pass; the nproc test reports as ignored
- [ ] `cargo clippy -p guardrail-linux --all-targets -- -D warnings` exits 0
- [ ] `cargo fmt --check` exits 0
- [ ] `guardrail-core` is unchanged (`git diff --quiet -- crates/guardrail-core`)
- [ ] No files outside the in-scope list are modified
- [ ] `plans/README.md` status row for 002 set to DONE

## STOP conditions

Stop and report (do not improvise) if:

- The `guardrail-core` API on disk differs from the "Current state" excerpts
  (e.g. `Backend::spawn`'s signature, or `SandboxConfig`'s public fields).
- `memory_limit_blocks_large_allocation` does **not** fail under the cap. Some
  environments (notably containers with overcommit quirks, or if `RLIMIT_AS` is
  already lower) change the behavior — report the observed exit status rather
  than weakening the assertion.
- `cpu_time_limit_kills_busy_loop` hangs longer than ~15s — that means the CPU
  limit isn't taking effect; report it (do not raise the limit to make it pass).
- You conclude you must touch `guardrail-core` or add `landlock`/`seccompiler`
  to make this compile — that is scope leakage; stop.
- `pre_exec` requires anything beyond `prctl` + `setrlimit` here — later plans
  own Landlock/seccomp; do not pull them forward.

## Maintenance notes

- The `pre_exec` closure in `lib.rs` is the single integration point for all
  in-process confinement. Plans 003 (Landlock) and 004/005 (seccomp) insert at
  the documented INSERTION POINT, in the order `setrlimit → Landlock → seccomp`
  (seccomp last). A reviewer should confirm new plans preserve that order and
  clone whatever `config` data they need **before** the `unsafe` block.
- The `unsafe`/async-signal-safety contract is load-bearing: anything added to
  the closure must avoid unwinding panics and minimize allocation. Flag any new
  closure code that allocates heavily or could panic.
- `RLIMIT_AS` caps *virtual* address space, which can be larger than RSS;
  programs that map a lot without touching it may hit the cap unexpectedly.
  Note this if users report false positives.
- The `guardrail-probe` exit-code contract (0 allowed / 3 denied / 2 usage) is a
  shared dependency of later test plans — keep it stable.
</content>
