# Plan 006: Add violation diagnostics (observability) to `guardrail`

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving on. If
> anything in "STOP conditions" occurs, stop and report — do not improvise.
> When done, update the status row for this plan in `plans/README.md`.
>
> **Drift check (run first)**:
> `git diff --stat <SHA-from-Status>..HEAD -- crates/guardrail-core/src/lib.rs crates/guardrail-linux/src/seccomp.rs`
> This plan adds types to `guardrail-core` and a diagnostics module to
> `guardrail-linux`. It assumes seccomp uses `SeccompAction::Trap` (SIGSYS) from
> plan 004. If `seccomp.rs`'s `VIOLATION_ACTION` is no longer `Trap`, the SIGSYS
> mapping here is wrong — treat as a STOP condition.

## Status

- **Priority**: P2
- **Effort**: M
- **Depends on**: plans/001, plans/002. Uses signals produced by plans/003
  (Landlock), plans/004 (seccomp network, **Trap/SIGSYS**), plans/005 (seccomp
  IPC). Land **after** 003/004/005 so the integration tests can exercise real
  violations; the core types could land earlier but the Linux logic needs them.
- **Risk**: LOW (additive; no change to confinement behavior)
- **Category**: dx / docs (observability)
- **Planned at**: commit `a1d2a66`, 2026-06-21 (re-run drift checks)

## Why this matters

`spec.md` §6: "When a program inside the sandbox is terminated or errors out due
to a policy violation, the sandbox must provide actionable feedback to the
creator, explicitly indicating which policy rule needs to be added to resolve
the issue." Without this, a caller (often an LLM agent) sees only a non-zero exit
or a signal death and cannot tell *why* — so it cannot self-correct by adding the
right policy.

This plan adds a best-effort diagnostic layer that maps a child's exit status,
**interpreted against the config that produced it**, into an actionable
[`Violation`] naming the likely cause and the policy method to call.

### What is and isn't knowable (read before coding — it shapes the honest design)

The parent process can observe the child's `ExitStatus` (exit code or
terminating signal) but **not** which syscall or path triggered a denial:

- **seccomp `Trap`** → child terminated by **`SIGSYS`** (signal 31). The parent
  sees the signal but not which syscall. Given the config, it can narrow the
  candidates (e.g. "network is `Deny` and IPC is `Strict` → either could be it").
- **resource limits** → `RLIMIT_CPU` soft limit raises **`SIGXCPU`** (24), hard
  raises **`SIGKILL`** (9); `RLIMIT_AS` makes allocations fail (often a non-zero
  exit, sometimes `SIGSEGV`/`SIGABRT` from a failed `malloc`). These overlap with
  ordinary crashes, so memory-limit attribution is a *hint*, not a certainty.
- **Landlock** → denials surface as `EACCES`/`EPERM` **inside the child**; the
  parent sees only whatever exit code the child chose. Landlock gives the parent
  **no signal**, so FS attribution is the weakest — we can only suggest checking
  FS grants when nothing else matches.

The diagnostics are therefore explicitly **best-effort and heuristic**. The doc
comments and the returned message must say so, so callers don't over-trust them.

## Current state

- `guardrail-core` exposes `SandboxConfig` (fields `network: NetworkPolicy`,
  `ipc: IpcPolicy`, `limits: ResourceLimits`, `fs: Vec<FsAccess>`), `Error`,
  `SandboxChild`, the policy enums. It has **no** diagnostics types yet.
- `guardrail-linux` applies seccomp with `VIOLATION_ACTION = SeccompAction::Trap`
  (plan 004) → violations kill the child with **SIGSYS**.
- `SandboxChild` (plan 001) wraps `std::process::Child` with `wait()`/`id()`/
  `into_inner()`. Signal extraction uses
  `std::os::unix::process::ExitStatusExt::signal()`.

## Decided design (follow exactly)

- **Types live in `guardrail-core`** (platform-agnostic), so any future backend
  can produce them. **Interpretation logic lives in `guardrail-linux`** (it deals
  in Linux signal numbers). This keeps `guardrail-core` free of `libc`.
- New core module `diagnostics` with:
  - `enum ViolationKind { Seccomp, ResourceLimit, Filesystem, Unknown }`
  - `struct Violation { kind: ViolationKind, summary: String, suggestions: Vec<String> }`
    + a `Display` impl that prints the summary followed by suggestion bullets.
- New linux function `guardrail_linux::diagnostics::explain(config, status) -> Option<Violation>`:
  - `None` when `status.success()` (nothing to explain).
  - Otherwise classify by signal/code against `config` and return a `Violation`
    with concrete, copy-pasteable suggestions (builder calls).
- Signal constants used: `SIGSYS = libc::SIGSYS`, `SIGXCPU = libc::SIGXCPU`,
  `SIGKILL = libc::SIGKILL` (don't hardcode numbers; use `libc`).

## Commands you will need

| Purpose          | Command                                                            | Expected   |
|------------------|--------------------------------------------------------------------|------------|
| Build core       | `cargo build -p guardrail-core`                                    | exit 0     |
| Build linux      | `cargo build -p guardrail-linux`                                   | exit 0     |
| Test (this plan) | `cargo test -p guardrail-linux --test diagnostics`                 | all pass   |
| Full test        | `cargo test --workspace`                                           | all pass   |
| Lint             | `cargo clippy --workspace --all-targets -- -D warnings`            | exit 0     |
| Format check     | `cargo fmt --check`                                                | exit 0     |
| Doc              | `cargo doc --no-deps -p guardrail-core -p guardrail-linux`         | exit 0     |

## Scope

**In scope** (create/modify only these):
- `crates/guardrail-core/src/diagnostics.rs` (create — `Violation`, `ViolationKind`)
- `crates/guardrail-core/src/lib.rs` — `mod diagnostics;` + re-export the two types
- `crates/guardrail-linux/src/diagnostics.rs` (create — `explain`)
- `crates/guardrail-linux/src/lib.rs` — `pub mod diagnostics;`
- `crates/guardrail-linux/tests/diagnostics.rs` (create)
- `plans/README.md` (status update)

**Out of scope**:
- Changing any confinement behavior (rlimit/fs/seccomp). This plan only
  *interprets* outcomes.
- `seccomp.rs`, `fs.rs`, `rlimit.rs` — do not modify.
- seccomp user-notification (`SECCOMP_RET_USER_NOTIF`) for precise syscall
  attribution — a much larger feature; explicitly deferred (see Maintenance).
- Changing `VIOLATION_ACTION` to `Errno` — if you think the diagnostics need
  that, STOP and report; it's a cross-cutting decision owned by plan 004.

## Version control

Repo uses **jj** colocated with git. **Do not commit/branch/push.** Leave changes
in the working copy.

## Steps

### Step 1: Add `Violation`/`ViolationKind` to `guardrail-core`

Create `crates/guardrail-core/src/diagnostics.rs`:

```rust
//! Best-effort observability for policy violations (`spec.md` §6).
//!
//! These types describe *why a sandboxed process likely failed* and *which
//! policy to add*. They are heuristic: the parent process cannot observe the
//! exact syscall or path a backend denied, so a [`Violation`] narrows the
//! cause from the exit status and the active configuration rather than
//! pinpointing it. Backends (e.g. `guardrail-linux`) produce these.

use std::fmt;

/// The category of a suspected policy violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ViolationKind {
    /// A syscall blocked by the seccomp filter (network or IPC).
    Seccomp,
    /// A resource limit (memory / CPU time / process count) was hit.
    ResourceLimit,
    /// Likely a filesystem denial (no parent-visible signal; inferred).
    Filesystem,
    /// Could not be attributed to a specific policy.
    Unknown,
}

/// An actionable explanation of a suspected policy violation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    /// The suspected category.
    pub kind: ViolationKind,
    /// One-line human summary of what was observed.
    pub summary: String,
    /// Concrete, copy-pasteable next steps (builder calls to add a policy).
    pub suggestions: Vec<String>,
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.summary)?;
        for s in &self.suggestions {
            write!(f, "\n  - {s}")?;
        }
        Ok(())
    }
}
```

Then in `crates/guardrail-core/src/lib.rs`:
- Add `mod diagnostics;` with the others.
- Re-export: `pub use diagnostics::{Violation, ViolationKind};`

**Verify**:
- `cargo build -p guardrail-core` → exit 0
- `cargo doc --no-deps -p guardrail-core` → exit 0

### Step 2: Implement `explain` in `guardrail-linux`

Create `crates/guardrail-linux/src/diagnostics.rs`:

```rust
//! Maps a sandboxed child's exit status to a best-effort [`Violation`].
//!
//! See the module-level note in `guardrail_core::diagnostics`: this is
//! heuristic. seccomp violations are observable (SIGSYS); Landlock denials are
//! NOT visible to the parent, so filesystem attribution is a fallback guess.

use std::process::ExitStatus;

use guardrail_core::{
    IpcPolicy, NetworkPolicy, SandboxConfig, Violation, ViolationKind,
};

/// Explain why `status` likely indicates a policy violation, given the `config`
/// the child ran under. Returns `None` if the child exited successfully.
pub fn explain(config: &SandboxConfig, status: ExitStatus) -> Option<Violation> {
    use std::os::unix::process::ExitStatusExt;

    if status.success() {
        return None;
    }

    if let Some(sig) = status.signal() {
        if sig == libc::SIGSYS {
            return Some(seccomp_violation(config));
        }
        if sig == libc::SIGXCPU || sig == libc::SIGKILL {
            if let Some(v) = resource_violation(config) {
                return Some(v);
            }
        }
    }

    // Non-success with no attributable signal. If memory was capped, a failed
    // allocation is plausible; otherwise the most common silent denial is the
    // filesystem (Landlock gives the parent no signal).
    if config.limits.memory_bytes.is_some() {
        return Some(Violation {
            kind: ViolationKind::ResourceLimit,
            summary: format!(
                "process exited unsuccessfully ({status}); it may have hit the memory limit"
            ),
            suggestions: vec![
                "raise or remove the memory cap: .memory_limit_mb(<larger>)".to_string(),
            ],
        });
    }

    Some(Violation {
        kind: ViolationKind::Filesystem,
        summary: format!(
            "process exited unsuccessfully ({status}); if it reported \
             'Permission denied' on a file, a filesystem grant is likely missing"
        ),
        suggestions: vec![
            "grant read access: .allow_read(\"<path>\")".to_string(),
            "grant write access: .allow_write(\"<path>\")".to_string(),
        ],
    })
}

fn seccomp_violation(config: &SandboxConfig) -> Violation {
    let mut suggestions = Vec::new();
    // Only suggest loosening policies that are currently restrictive.
    if config.network != NetworkPolicy::Full {
        suggestions.push(
            "if it needs network: .network(NetworkPolicy::OutboundOnly) (or ::Full to bind/listen)"
                .to_string(),
        );
    }
    if config.ipc != IpcPolicy::Relaxed {
        suggestions.push(
            "if it needs shared memory / message queues: .ipc(IpcPolicy::Relaxed)".to_string(),
        );
    }
    if suggestions.is_empty() {
        // Network is Full and IPC is Relaxed already: the only thing still
        // blocked is process inspection (ptrace/process_vm_*), which is never
        // unblockable by design.
        suggestions.push(
            "the blocked call was process inspection (ptrace/process_vm_*), which the \
             sandbox never permits; the program cannot run under guardrail"
                .to_string(),
        );
    }
    Violation {
        kind: ViolationKind::Seccomp,
        summary: "process was killed by SIGSYS — a syscall blocked by the seccomp filter \
                  (network or IPC)"
            .to_string(),
        suggestions,
    }
}

fn resource_violation(config: &SandboxConfig) -> Option<Violation> {
    let mut suggestions = Vec::new();
    if config.limits.cpu_time_secs.is_some() {
        suggestions.push("raise the CPU cap: .cpu_time_limit_secs(<larger>)".to_string());
    }
    if config.limits.memory_bytes.is_some() {
        suggestions.push("raise the memory cap: .memory_limit_mb(<larger>)".to_string());
    }
    if suggestions.is_empty() {
        return None; // killed by a signal but no resource limit was set
    }
    Some(Violation {
        kind: ViolationKind::ResourceLimit,
        summary: "process was killed by a resource limit (CPU time or memory)".to_string(),
        suggestions,
    })
}
```

In `crates/guardrail-linux/src/lib.rs`, add `pub mod diagnostics;` (alongside the
private `mod fs/rlimit/seccomp`). This one is `pub` — it's part of the crate's
API.

**Verify**:
- `cargo build -p guardrail-linux` → exit 0
- `cargo clippy -p guardrail-linux --lib -- -D warnings` → exit 0

### Step 3: Integration tests — `diagnostics.rs`

Create `crates/guardrail-linux/tests/diagnostics.rs`. These reuse the
`guardrail-probe` helper and real confinement, then assert the *kind* of
violation (not exact wording). Skip-guard seccomp tests if seccomp can't install
(rare; this host supports it).

```rust
use std::process::{Command, Stdio};

use guardrail_core::{IpcPolicy, NetworkPolicy, SandboxBuilder, SandboxConfig, ViolationKind};
use guardrail_linux::diagnostics::explain;
use guardrail_linux::LinuxBackend;

fn probe(args: &[&str]) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_guardrail-probe"));
    c.args(args).stdout(Stdio::null()).stderr(Stdio::null());
    c
}

fn base() -> SandboxBuilder {
    let exe = std::path::PathBuf::from(env!("CARGO_BIN_EXE_guardrail-probe"));
    SandboxBuilder::new().allow_read(exe.parent().unwrap().to_path_buf())
}

fn run(config: &SandboxConfig, args: &[&str]) -> std::process::ExitStatus {
    let mut child = config
        .spawn_with(&LinuxBackend::new(), probe(args))
        .expect("spawn");
    child.wait().expect("wait")
}

#[test]
fn success_yields_no_violation() {
    let config = base().build();
    let status = run(&config, &["echo-env", "PATH"]);
    assert!(explain(&config, status).is_none());
}

#[test]
fn blocked_network_is_diagnosed_as_seccomp() {
    let config = base().network(NetworkPolicy::Deny).build();
    let status = run(&config, &["socket-inet"]);
    let v = explain(&config, status).expect("should diagnose a violation");
    assert_eq!(v.kind, ViolationKind::Seccomp);
    assert!(
        !v.suggestions.is_empty(),
        "a seccomp violation must suggest a network/IPC policy to relax"
    );
}

#[test]
fn blocked_ipc_is_diagnosed_as_seccomp() {
    let config = base().ipc(IpcPolicy::Strict).build();
    let status = run(&config, &["shm"]);
    let v = explain(&config, status).expect("should diagnose a violation");
    assert_eq!(v.kind, ViolationKind::Seccomp);
}

#[test]
fn cpu_limit_is_diagnosed_as_resource_limit() {
    let config = base().cpu_time_limit_secs(1).build();
    let status = run(&config, &["spin"]);
    let v = explain(&config, status).expect("should diagnose a violation");
    assert_eq!(v.kind, ViolationKind::ResourceLimit);
}

#[test]
fn violation_display_includes_summary_and_suggestions() {
    let config = base().network(NetworkPolicy::Deny).build();
    let status = run(&config, &["socket-inet"]);
    let v = explain(&config, status).unwrap();
    let rendered = v.to_string();
    assert!(rendered.contains("SIGSYS"));
    assert!(rendered.contains("  - "), "Display should bullet the suggestions");
}
```

**Verify**:
- `cargo test -p guardrail-linux --test diagnostics` → all pass
- `cargo test --workspace` → all suites pass

## Test plan

- `diagnostics.rs`: success → `None`; a `Deny`'d network socket → `Seccomp`
  kind with non-empty suggestions; a `Strict` IPC `shm` → `Seccomp`; a CPU cap
  on a spinner → `ResourceLimit`; and the `Display` rendering includes the
  summary + bulleted suggestions. Asserts on `ViolationKind` and structural
  facts, not exact prose (so wording can evolve).
- Reuses the `guardrail-probe` helper and real confinement (these tests
  implicitly re-validate that 004/005/002 still enforce).
- Model after `tests/network.rs` / `tests/ipc.rs`.

## Done criteria

Machine-checkable. ALL must hold:

- [ ] `cargo build -p guardrail-core` and `-p guardrail-linux` exit 0
- [ ] `guardrail_core::{Violation, ViolationKind}` are re-exported (referenced in
      the linux crate without a path error)
- [ ] `cargo test -p guardrail-linux --test diagnostics` exits 0 (5 tests pass)
- [ ] `cargo test --workspace` exits 0 (all suites across both crates)
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` exits 0
- [ ] `cargo fmt --check` exits 0
- [ ] `cargo doc --no-deps -p guardrail-core -p guardrail-linux` exits 0
- [ ] confinement modules unchanged
      (`git diff --quiet -- crates/guardrail-linux/src/seccomp.rs crates/guardrail-linux/src/fs.rs crates/guardrail-linux/src/rlimit.rs`)
- [ ] No files outside the in-scope list are modified
- [ ] `plans/README.md` status row for 006 set to DONE

## STOP conditions

Stop and report (do not improvise) if:

- `seccomp.rs`'s `VIOLATION_ACTION` is not `SeccompAction::Trap` — the SIGSYS
  mapping is then invalid. Report; do not guess a new mapping.
- `blocked_network_is_diagnosed_as_seccomp` shows the child exiting with code 3
  (not SIGSYS) — that means seccomp is returning `Errno`, not `Trap`, or isn't
  installed. Reconcile with plan 004 before adjusting this plan.
- `cpu_limit_is_diagnosed_as_resource_limit` sees a signal other than
  SIGXCPU/SIGKILL on this host — report the actual signal so the mapping can be
  widened deliberately.
- You find you must modify a confinement module to make a test pass — scope leak.

## Maintenance notes

- **This layer is heuristic by construction.** The honest limitation: the parent
  cannot see the denied syscall or path. The summaries say "likely"/"may" — keep
  that hedging; do not phrase guesses as certainties.
- **Precise attribution is possible but costly**: seccomp user notification
  (`SECCOMP_RET_USER_NOTIF`) plus a supervisor thread could report the exact
  blocked syscall, and a Landlock audit-log reader (ABI v7, available on this
  host's kernel) could report denied paths. Both are substantial features
  deliberately deferred — note them if a consumer needs exact diagnostics.
- If plan 004 ever switches `VIOLATION_ACTION` to `Errno`, seccomp violations
  stop producing SIGSYS; this module's `Seccomp` branch would then need to read
  the child's stderr or an errno channel instead. Keep the two in sync.
- A reviewer should confirm `explain` only *suggests relaxing policies that are
  currently set* (e.g. it must not tell a user with `NetworkPolicy::Full` to
  "add network access").
</content>
