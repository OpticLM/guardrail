# Plan 008: Launch Windows children under Job Objects with owned handles

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving on. If any
> STOP condition occurs, stop and report; do not improvise. When done, update
> the status row for this plan in `plans/README.md`.
>
> **Drift check (run first)**:
> `jj diff --from 4e4f9327 -- crates/guardrail-core/src/process.rs crates/guardrail-core/src/backend.rs crates/guardrail-windows Cargo.toml`
> If in-scope code changed since this plan was written, compare the Current
> state excerpts before proceeding.

## Status

- **Priority**: P1
- **Effort**: L
- **Risk**: HIGH (raw Windows process creation and a core process-handle change)
- **Depends on**: plans/007
- **Category**: security / migration
- **Planned at**: commit `4e4f9327`, 2026-06-21

## Why this matters

The Windows backend must start the target process in a controlled state, assign
it to a Job Object, and keep a handle that kills the process tree when dropped.
`std::process::Command` cannot apply AppContainer extended startup attributes on
stable Rust; a local compile check showed `ProcThreadAttributeList` and
`spawn_with_attributes` are still behind `windows_process_extensions_raw_attribute`.
This plan adds the Windows-owned process handle path that later AppContainer
confinement can reuse, while keeping the Linux `std::process::Child` path intact.

## Current state

- `Cargo.toml:3-7` includes `crates/guardrail-windows` as a workspace member,
  and `Cargo.toml:21` defines workspace dependency `windows-sys = "0.61"`.
- `crates/guardrail-core/src/process.rs:12` defines `SandboxChild` as a thin
  wrapper around `std::process::Child`.
- `crates/guardrail-core/src/process.rs:21-37` exposes `wait`, `kill`,
  `inner_mut`, and `into_inner`; Linux tests use `into_inner().wait_with_output()`.
- `crates/guardrail-core/src/backend.rs:17-19` requires every backend to return
  a `SandboxChild`.
- `crates/guardrail-linux/src/lib.rs:33` constructs `SandboxChild::from(child)`
  after `std::process::Command::spawn()`.
- `crates/guardrail-windows/Cargo.toml:9-10` currently depends only on
  `guardrail-core`.
- `crates/guardrail-windows/src/lib.rs:23-28` currently returns
  `Error::Unsupported("guardrail-windows confinement is not implemented yet; run plans 008-009")`
  from the Windows backend stub.
- `windows-sys 0.61.2` exposes the needed Job Object APIs in
  `windows_sys::Win32::System::JobObjects`: `CreateJobObjectW`,
  `SetInformationJobObject`, `AssignProcessToJobObject`,
  `TerminateJobObject`, `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`,
  `JOB_OBJECT_LIMIT_JOB_MEMORY`, `JOB_OBJECT_LIMIT_ACTIVE_PROCESS`, and
  `JOB_OBJECT_LIMIT_JOB_TIME`.

## Commands you will need

| Purpose | Command | Expected on success |
|---------|---------|---------------------|
| Build core | `cargo build -p guardrail-core` | exit 0 |
| Build windows | `cargo build -p guardrail-windows` | exit 0 |
| Unit tests | `cargo test -p guardrail-windows` | Windows-only unit tests pass |
| Workspace | `cargo test --workspace` | exit 0 |
| Lint | `cargo clippy --workspace --all-targets -- -D warnings` | exit 0 |
| Format | `cargo fmt --check` | exit 0 |

## Scope

**In scope**:
- `crates/guardrail-core/src/process.rs`
- `crates/guardrail-core/src/backend.rs` docs only, if needed
- `crates/guardrail-windows/Cargo.toml`
- `crates/guardrail-windows/src/lib.rs`
- `crates/guardrail-windows/src/handle.rs` (create)
- `crates/guardrail-windows/src/job.rs` (create)
- `crates/guardrail-windows/src/process.rs` (create)
- `crates/guardrail-windows/tests/resource_limits.rs` (create, Windows-gated)
- `plans/README.md`

**Out of scope**:
- AppContainer profiles, network denial, filesystem ACL grants. Those are plan
  009.
- Diagnostics mapping. That is plan 010.
- Linux confinement behavior. Linux should keep constructing
  `SandboxChild::from(std::process::Child)`.

## Version control

Repo uses **jj** colocated with git. Do not commit, branch, push, or use git
checkout/reset. Leave changes in the working copy.

## Steps

### Step 1: Extend `SandboxChild` for Windows-owned handles

Refactor `crates/guardrail-core/src/process.rs` so `SandboxChild` can wrap:
- the existing `std::process::Child` variant for Unix/Linux and compatibility;
- a Windows raw process variant behind `#[cfg(windows)]`.

Keep these public behaviors:
- `SandboxChild::from(Child)` still works for Linux.
- `id()`, `wait()`, and `kill()` keep the same signatures.
- `inner_mut()` and `into_inner()` remain available for the `std::process::Child`
  variant. If called on the Windows variant, return a clear panic message such
  as `"raw Windows SandboxChild has no std::process::Child"`. Do not silently
  fabricate a `Child`.

Add a Windows-only constructor for platform crates:

```rust
#[cfg(windows)]
pub unsafe fn from_windows_handles(
    process: std::os::windows::io::OwnedHandle,
    job: std::os::windows::io::OwnedHandle,
    pid: u32,
) -> Self
```

The Windows variant must:
- `wait()` via `WaitForSingleObject(process, INFINITE)` and
  `GetExitCodeProcess`, returning a Windows `ExitStatus`.
- `kill()` via `TerminateJobObject(job, 1)` so descendants die too.
- keep the Job Object handle alive until the `SandboxChild` is dropped.

**Verify**: `cargo test -p guardrail-core` -> all existing tests and doctest
still pass.

### Step 2: Add Windows API dependencies

In `crates/guardrail-windows/Cargo.toml`, add target-specific Windows deps:

```toml
[target.'cfg(windows)'.dependencies]
windows-sys = { workspace = true, features = [
    "Win32_Foundation",
    "Win32_System_JobObjects",
    "Win32_System_Threading",
    "Win32_System_WindowsProgramming",
] }
```

Keep `guardrail-core.workspace = true`.

**Verify**: `cargo build -p guardrail-windows` -> exit 0.

### Step 3: Implement RAII handle helpers

Create `crates/guardrail-windows/src/handle.rs` with small helpers:
- convert raw `HANDLE` returns into `OwnedHandle`, treating null/invalid handles
  as `std::io::Error::last_os_error()`;
- close thread handles promptly after `ResumeThread`;
- convert Windows BOOL/return-code APIs to `Result<(), std::io::Error>`.

All unsafe blocks must have concrete safety comments. Match the Linux style:
short comments explaining pointer lifetime and ownership.

**Verify**: `cargo clippy -p guardrail-windows --lib -- -D warnings` -> exit 0.

### Step 4: Implement Job Object creation and limits

Create `crates/guardrail-windows/src/job.rs`:
- `create(config: &SandboxConfig) -> Result<OwnedHandle, Error>`.
- Call `CreateJobObjectW(null_mut(), null())`.
- Configure `JOBOBJECT_EXTENDED_LIMIT_INFORMATION` with:
  - always: `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`;
  - `limits.memory_bytes`: `JOB_OBJECT_LIMIT_JOB_MEMORY` and
    `JobMemoryLimit`;
  - `limits.max_processes`: `JOB_OBJECT_LIMIT_ACTIVE_PROCESS` and
    `ActiveProcessLimit`;
  - `limits.cpu_time_secs`: `JOB_OBJECT_LIMIT_JOB_TIME` and
    `PerJobUserTimeLimit` in 100-nanosecond units.
- Call `SetInformationJobObject(..., JobObjectExtendedLimitInformation, ...)`.

Return `Error::confinement("job", err)` for Job Object setup failures.

**Verify**: `cargo build -p guardrail-windows` -> exit 0.

### Step 5: Implement suspended process launch and assignment

Create `crates/guardrail-windows/src/process.rs`:
- Read the target from the incoming `std::process::Command` using stable getters
  (`get_program`, `get_args`, `get_envs`, `get_current_dir`).
- Build a Windows command line with a tested quoting helper. Include unit tests
  for spaces, quotes, backslashes before quotes, and empty args.
- Build a UTF-16 environment block from `command.get_envs()`. Because
  `SandboxConfig::spawn_with` already called `env_clear()` and `envs(&self.env)`,
  this block should contain only the explicit env map plus any per-command env
  changes.
- Use inherited standard handles for this first Windows raw-launch path. Stable
  Rust exposes program/args/env/cwd getters on `Command`, but not stable getters
  for the configured `Stdio`. Do not claim custom `stdin`/`stdout`/`stderr`
  preservation in docs or tests; plan 010 uses exit-code/file based probes for
  that reason.
- Call `CreateProcessW` with `CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT`.
- Assign the suspended process to the job with `AssignProcessToJobObject`.
- Resume the primary thread with `ResumeThread`.
- Close the thread handle.
- Return a `SandboxChild::from_windows_handles(process_handle, job_handle, pid)`.

Do not use `std::process::Command::spawn()` in this path. The child must not run
before it is assigned to the Job Object.

**Verify**: `cargo build -p guardrail-windows` -> exit 0.

### Step 6: Wire `WindowsBackend`

In `crates/guardrail-windows/src/lib.rs`, replace the plan-007 Unsupported stub
on Windows with:
- create Job Object from `config`;
- launch target suspended;
- assign/resume;
- return `SandboxChild`.

Keep the non-Windows stub returning `Unsupported`.

**Verify**:
- `cargo test -p guardrail-windows` -> unit tests pass.
- `cargo test --workspace` -> exits 0.

### Step 7: Add Windows resource-limit integration tests

Create `crates/guardrail-windows/tests/resource_limits.rs` with
`#![cfg(windows)]`. Model the assertions after
`crates/guardrail-linux/tests/resource_limits.rs`, but use Windows-safe helper
commands if the Windows probe is not created until plan 010:
- A simple `cmd /C exit 0` runs under a default config.
- A busy-loop/memory test may be `#[ignore]` until the probe exists in plan 010.
- A `max_processes(1)` test can spawn a command that attempts to start a child
  and assert failure, but mark ignored if it is flaky on the host.

Keep this plan's tests focused on Job Object lifecycle. Full policy tests arrive
in plan 010.

**Verify**: `cargo test -p guardrail-windows --test resource_limits` -> exits 0
with any intentionally flaky tests ignored.

## Test plan

- Unit-test command-line quoting and UTF-16 environment block construction.
- Integration-test that a basic process runs under `WindowsBackend`.
- Add at least one non-ignored Job Object behavior test if reliable on the host;
  otherwise document ignored tests and rely on plan 010's probe for stronger
  coverage.

## Done criteria

- [ ] `SandboxChild` supports both `std::process::Child` and Windows raw handles.
- [ ] Windows `wait()` and `kill()` work through process/job handles.
- [ ] `WindowsBackend` creates a suspended process, assigns it to a Job Object,
      then resumes it.
- [ ] Job Object always uses `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`.
- [ ] `cargo test --workspace` exits 0.
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` exits 0.
- [ ] `cargo fmt --check` exits 0.
- [ ] `plans/README.md` row 008 is updated to DONE.

## STOP conditions

Stop and report if:
- Stable Rust cannot construct `ExitStatus` from a Windows exit code. Do not
  invent an incompatible wait API; report the compiler error and the exact Rust
  version.
- `std::process::Command` getters are insufficient to reconstruct program,
  args, env, and cwd.
- The process starts running before `AssignProcessToJobObject` succeeds.
- A reliable process tree kill requires changing `SandboxChild` public API
  beyond the methods listed in Step 1.

## Maintenance notes

The public `Backend` trait still accepts `std::process::Command`, but the
Windows backend must not use `Command::spawn()` because AppContainer and Job
Object safety require pre-launch control. Reviewers should scrutinize command
line quoting, handle ownership, and error paths that might resume a process
after a failed confinement stage. This plan deliberately leaves custom stdio
preservation as a follow-up API problem: stable `Command` does not expose the
configured `Stdio`, so the Windows raw-launch path should be documented as
inherited-stdio only until the core command model is expanded.
