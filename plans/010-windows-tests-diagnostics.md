# Plan 010: Add Windows probe tests and violation diagnostics

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving on. If any
> STOP condition occurs, stop and report; do not improvise. When done, update
> the status row for this plan in `plans/README.md`.
>
> **Drift check (run first)**:
> `jj diff --from 44fcf4e0 -- crates/guardrail-core/src/diagnostics.rs crates/guardrail-windows crates/guardrail-linux/tests crates/guardrail-linux/src/bin/guardrail-probe.rs`
> If in-scope code changed since this plan was written, compare Current state
> excerpts against live code before proceeding.

## Status

- **Priority**: P2
- **Effort**: M
- **Risk**: MED (test helper and heuristic diagnostics)
- **Depends on**: plans/008, plans/009
- **Category**: tests / dx
- **Planned at**: commit `44fcf4e0`, 2026-06-21

## Why this matters

The Linux backend has deterministic integration tests driven by
`guardrail-probe`; the Windows backend needs the same intent-level coverage.
The core diagnostics types already exist, but the Linux diagnostic mapper is
Linux-specific (`SIGSYS`, `SIGXCPU`, Landlock fallback). Windows needs a mapper
that explains AppContainer filesystem/network denials and Job Object resource
terminations without pretending to know more than the parent can observe.

## Current state

- `crates/guardrail-core/src/diagnostics.rs` defines
  `ViolationKind::{Seccomp, ResourceLimit, Filesystem, Unknown}` and
  `Violation { kind, summary, suggestions }`.
- `crates/guardrail-linux/src/diagnostics.rs:12-30` maps Linux `ExitStatus`
  signals to heuristic violations.
- `crates/guardrail-linux/src/bin/guardrail-probe.rs` provides deterministic
  commands: `echo-env`, `alloc`, `spin`, `read-file`, `write-file`,
  `socket-inet`, `tcp-bind`, `shm`, and `ptrace-self`.
- Windows plans 008 and 009 should provide real Job Object and AppContainer
  confinement before this plan starts.

## Commands you will need

| Purpose | Command | Expected on success |
|---------|---------|---------------------|
| Build probe | `cargo build -p guardrail-windows --bin guardrail-windows-probe` | exit 0 |
| Env tests | `cargo test -p guardrail-windows --test environment` | all pass |
| Resource tests | `cargo test -p guardrail-windows --test resource_limits` | all pass, flaky tests ignored |
| Policy tests | `cargo test -p guardrail-windows --test policy` | all pass, loopback tests may be ignored |
| Diagnostics tests | `cargo test -p guardrail-windows --test diagnostics` | all pass |
| Workspace | `cargo test --workspace` | exit 0 |
| Lint | `cargo clippy --workspace --all-targets -- -D warnings` | exit 0 |
| Format | `cargo fmt --check` | exit 0 |

## Scope

**In scope**:
- `crates/guardrail-windows/Cargo.toml`
- `crates/guardrail-windows/src/bin/guardrail-windows-probe.rs` (create)
- `crates/guardrail-windows/src/diagnostics.rs` (create)
- `crates/guardrail-windows/src/lib.rs`
- `crates/guardrail-windows/tests/environment.rs` (create)
- `crates/guardrail-windows/tests/resource_limits.rs` (extend from plan 008)
- `crates/guardrail-windows/tests/policy.rs` (extend from plan 009)
- `crates/guardrail-windows/tests/diagnostics.rs` (create)
- `plans/README.md`

**Out of scope**:
- Changing the core diagnostics enum unless Windows has a concrete, tested need
  for a new `ViolationKind`.
- Changing Linux probe/test behavior.
- Making loopback policy a new core API.

## Version control

Repo uses **jj** colocated with git. Do not commit, branch, push, or reset. Leave
changes in the working copy.

## Steps

### Step 1: Add a Windows probe binary

Add a `[[bin]]` entry to `crates/guardrail-windows/Cargo.toml`:

```toml
[[bin]]
name = "guardrail-windows-probe"
path = "src/bin/guardrail-windows-probe.rs"
```

Create `src/bin/guardrail-windows-probe.rs` with Windows-safe commands matching
the Linux probe where possible:
- `echo-env <NAME>`: print env var or empty string, exit 0.
- `check-env <NAME> <EXPECTED>`: exit 0 if the env var equals `EXPECTED`, else
  exit 3. This avoids relying on piped stdout because plan 008's raw Windows
  launch path intentionally supports inherited stdio only.
- `alloc <MB>`: reserve, resize, and touch memory; exit 0 if successful, 3 on
  allocation failure.
- `spin`: busy-loop forever.
- `read-file <PATH>`: exit 0 on read success, 3 on error.
- `write-file <PATH>`: exit 0 on write success, 3 on error.
- `tcp-connect <HOST> <PORT>`: exit 0 on connect success, 3 on error.
- `tcp-bind`: bind `127.0.0.1:0`, exit 0 on success, 3 on error.

Do not add IPC probes in this plan; Windows IPC is documented no-op.

**Verify**: `cargo build -p guardrail-windows --bin guardrail-windows-probe` ->
exit 0.

### Step 2: Add environment tests

Create `crates/guardrail-windows/tests/environment.rs` with `#![cfg(windows)]`.
Model after `crates/guardrail-linux/tests/environment.rs`:
- Set `GUARDRAIL_SECRET` in the parent, spawn probe
  `check-env GUARDRAIL_SECRET leaked` with `SandboxBuilder::new().build()`, and
  assert the probe exits non-zero because the inherited parent secret was not
  present.
- Add `.env("GREETING", "hello")`, spawn `check-env GREETING hello`, and assert
  the probe exits successfully.

Do not use piped stdout for these tests unless plan 008 also solved custom
stdio preservation for raw Windows process creation.

**Verify**: `cargo test -p guardrail-windows --test environment` -> both tests
pass.

### Step 3: Expand resource-limit tests

Extend `crates/guardrail-windows/tests/resource_limits.rs`:
- `memory_limit_blocks_large_allocation`: small memory cap, `alloc 512`, assert
  non-success.
- `without_limit_the_same_allocation_succeeds`: control test for the probe.
- `cpu_time_limit_kills_busy_loop`: one-second CPU/job-time limit, `spin`, assert
  non-success within a bounded wall-clock timeout.
- `process_limit_is_applied`: may be `#[ignore]` if Windows nested process-count
  behavior is host-sensitive.

Model assertions after the Linux resource tests, but use Windows exit/status
semantics.

**Verify**: `cargo test -p guardrail-windows --test resource_limits` ->
non-ignored tests pass.

### Step 4: Expand policy tests

Extend `crates/guardrail-windows/tests/policy.rs` from plan 009:
- Filesystem read denied without grant and allowed with `allow_read`.
- Write denied under read grant and allowed with `allow_write`.
- Network deny blocks `tcp-connect`.
- `OutboundOnly` connect behavior is tested if the host permits AppContainer
  loopback; otherwise mark the loopback-dependent test ignored and document the
  host setup needed.
- `Full` allows `tcp-bind` if AppContainer capabilities support it; if plan 009
  stopped on `Full`, keep this test pending with that BLOCKED reason in the
  README.

**Verify**: `cargo test -p guardrail-windows --test policy` -> non-ignored tests
pass.

### Step 5: Add Windows diagnostics

Create `crates/guardrail-windows/src/diagnostics.rs`:
- `pub fn explain(config: &SandboxConfig, status: ExitStatus) -> Option<Violation>`.
- Return `None` on success.
- If resource limits are set and the process was killed/non-success, return
  `ViolationKind::ResourceLimit` with suggestions to raise the active caps.
- If no resource signal is clear but the child exited non-zero under restrictive
  network policy, return `ViolationKind::Unknown` or `Filesystem` only when the
  test evidence supports it. Do not invent a `Seccomp` mapping on Windows.
- Suggestions must name builder calls (`.allow_read`, `.allow_write`,
  `.network(NetworkPolicy::OutboundOnly)`) and use "likely"/"may" language.

Export `pub mod diagnostics;` from `crates/guardrail-windows/src/lib.rs`.

**Verify**: `cargo build -p guardrail-windows` -> exit 0.

### Step 6: Add diagnostics tests

Create `crates/guardrail-windows/tests/diagnostics.rs` with `#![cfg(windows)]`:
- Success yields `None`.
- Memory/CPU constrained probe yields `ViolationKind::ResourceLimit`.
- Filesystem denial yields a violation with at least one `.allow_read` or
  `.allow_write` suggestion.
- Network denial yields a violation with a `.network(...)` suggestion.
- Display output includes summary plus `  - ` suggestion bullets.

Assert on kind and suggestion structure, not exact prose.

**Verify**: `cargo test -p guardrail-windows --test diagnostics` -> all pass.

## Test plan

This plan creates the Windows equivalent of the Linux intent tests. The tests
exercise observable behavior through a probe binary rather than internal
implementation order. Loopback network tests may be ignored if AppContainer
loopback is not enabled on the host; all file, environment, and resource tests
should be non-ignored.

## Done criteria

- [ ] `guardrail-windows-probe` exists and builds.
- [ ] Environment scrubbing tests pass on Windows.
- [ ] Resource limit tests pass, with only host-sensitive process-count tests
      ignored.
- [ ] Filesystem grant tests pass and prove read grant does not permit write.
- [ ] Network deny has at least one non-ignored test.
- [ ] `guardrail_windows::diagnostics::explain` is exported and tested.
- [ ] `cargo test --workspace` exits 0.
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` exits 0.
- [ ] `cargo fmt --check` exits 0.
- [ ] `plans/README.md` row 010 is updated to DONE.

## STOP conditions

Stop and report if:
- AppContainer filesystem denials cannot be distinguished enough to give honest
  suggestions; report the observed `ExitStatus` and stderr instead of guessing.
- ACL cleanup from plan 009 is flaky under the policy tests.
- Network tests require permanent machine-level AppContainer loopback changes
  without an ignored/manual-test fallback.

## Maintenance notes

Keep Windows diagnostics explicitly heuristic. Unlike Linux seccomp `Trap`, the
parent will not always get a unique signal for AppContainer denials. Reviewers
should check that suggestions are useful without overstating certainty, and that
no test passes because it accidentally ran outside AppContainer.
