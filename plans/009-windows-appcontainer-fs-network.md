# Plan 009: Apply AppContainer network and filesystem confinement on Windows

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving on. If any
> STOP condition occurs, stop and report; do not improvise. When done, update
> the status row for this plan in `plans/README.md`.
>
> **Drift check (run first)**:
> `jj diff --from 44fcf4e0 -- crates/guardrail-windows crates/guardrail-core/src/policy.rs spec.md plans/README.md`
> If in-scope code changed since this plan was written, compare the Current
> state excerpts below before proceeding.

## Status

- **Priority**: P1
- **Effort**: L
- **Risk**: HIGH (Windows security descriptors and AppContainer launch)
- **Depends on**: plans/008
- **Category**: security
- **Planned at**: commit `44fcf4e0`, 2026-06-21

## Why this matters

`spec.md` section 4.2 says the Windows backend should use AppContainer for
network and file confinement, and Job Objects for resource control. Job Objects
alone do not block network, reads, or writes. This plan creates a per-run
AppContainer profile with no network capabilities by default, applies only the
capabilities implied by `NetworkPolicy`, and grants filesystem access by
temporarily adding ACEs for the AppContainer SID to explicit `FsAccess` paths.

## Current state

- `spec.md:94-100` names "Windows Backend: AppContainer + Job Objects + Temp
  Workspace" and says no `internetClient` capability means zero network by
  default.
- `spec.md:97-100` also mentions cleanup of ACL and SID artifacts.
- `crates/guardrail-core/src/policy.rs:10-22` defines `FsAccess::{Read, Write}`.
- `crates/guardrail-core/src/policy.rs:24-35` defines
  `NetworkPolicy::{Deny, OutboundOnly, Full}`.
- `crates/guardrail-core/src/policy.rs:37-50` defines `IpcPolicy`; the spec says
  no special Windows IPC operations are required.
- `windows-sys 0.61.2` exposes AppContainer functions in
  `windows_sys::Win32::Security::Isolation`: `CreateAppContainerProfile`,
  `DeleteAppContainerProfile`, `DeriveAppContainerSidFromAppContainerName`, and
  `GetAppContainerFolderPath`.
- Plan 008 must already provide raw `CreateProcessW` launch with extended
  startup attribute support or an equivalent raw launch path. AppContainer
  cannot be applied after a normal process has already started.

## Commands you will need

| Purpose | Command | Expected on success |
|---------|---------|---------------------|
| Build windows | `cargo build -p guardrail-windows` | exit 0 |
| Policy tests | `cargo test -p guardrail-windows --test policy` | Windows policy tests pass |
| Workspace | `cargo test --workspace` | exit 0 |
| Lint | `cargo clippy --workspace --all-targets -- -D warnings` | exit 0 |
| Format | `cargo fmt --check` | exit 0 |

## Scope

**In scope**:
- `crates/guardrail-windows/Cargo.toml`
- `crates/guardrail-windows/src/appcontainer.rs` (create)
- `crates/guardrail-windows/src/acl.rs` (create)
- `crates/guardrail-windows/src/process.rs`
- `crates/guardrail-windows/src/lib.rs`
- `crates/guardrail-windows/tests/policy.rs` (create)
- `plans/README.md`

**Out of scope**:
- Changing core policy enum names or semantics.
- Adding a Windows-only loopback policy variant. The existing core enum has no
  such variant; defer API expansion unless a maintainer requests it.
- macOS backend or top-level facade crate.
- Permanent ACL changes to broad host directories.

## Version control

Repo uses **jj** colocated with git. Do not commit, branch, push, or reset. Leave
changes in the working copy.

## Steps

### Step 1: Add required Windows API features

Add `windows-sys` features needed for AppContainer and ACL work:
- `Win32_Security`
- `Win32_Security_Isolation`
- `Win32_Storage_FileSystem`
- `Win32_System_Memory`

Keep features target-specific under `[target.'cfg(windows)'.dependencies]`.

**Verify**: `cargo build -p guardrail-windows` -> exit 0.

### Step 2: Create a per-run AppContainer profile

Create `crates/guardrail-windows/src/appcontainer.rs`:
- Build a unique profile name, e.g. `guardrail-{process_id}-{monotonic_counter}`.
- Call `CreateAppContainerProfile` with display/description strings and a
  capabilities array derived from `NetworkPolicy`.
- For `NetworkPolicy::Deny`, pass no internet capabilities.
- For `NetworkPolicy::OutboundOnly`, add `internetClient` only.
- For `NetworkPolicy::Full`, add `internetClient` and the server capability
  needed to bind/listen if the Windows capability exists on this target. If the
  exact bind/listen capability cannot be represented through AppContainer
  capabilities, STOP and report rather than silently treating `Full` as
  outbound-only.
- Call `DeriveAppContainerSidFromAppContainerName` and store the SID.
- Implement `Drop` to call `DeleteAppContainerProfile`.

Use `Error::confinement("appcontainer", err)` for profile/SID errors.

**Verify**: `cargo test -p guardrail-windows appcontainer` -> AppContainer unit
tests pass on Windows.

### Step 3: Temporarily grant filesystem ACLs for declared paths

Create `crates/guardrail-windows/src/acl.rs`:
- For each `FsAccess::Read(path)`, add an allow ACE for the AppContainer SID
  granting read/list/execute rights needed to load files beneath the path.
- For each `FsAccess::Write(path)`, add an allow ACE granting read + write +
  create rights beneath the path.
- Before changing a descriptor, capture the original security descriptor/DACL.
- Store all originals in an RAII guard and restore them in reverse order on
  `Drop`.
- If restore fails, print a clear warning to stderr naming the path but never
  including secret file contents.

This is a deliberate Windows-specific tradeoff from `spec.md` section 4.2. Do
not add ACEs outside explicit `FsAccess` paths.

**Verify**: `cargo build -p guardrail-windows` -> exit 0.

### Step 4: Launch the process with AppContainer security capabilities

Extend the raw launch path from plan 008:
- Initialize a `PROC_THREAD_ATTRIBUTE_LIST`.
- Fill `SECURITY_CAPABILITIES` with the AppContainer SID and capabilities.
- Add it with `UpdateProcThreadAttribute(..., PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, ...)`.
- Launch with `EXTENDED_STARTUPINFO_PRESENT`.
- Keep the AppContainer profile and ACL guard alive at least until process
  launch has succeeded. Prefer keeping them alive inside the Windows
  `SandboxChild` variant until the child exits, so long-running children do not
  lose access mid-run.

If plan 008 did not implement raw extended startup attributes, STOP here and
complete that foundation first.

**Verify**: `cargo build -p guardrail-windows` -> exit 0.

### Step 5: Treat Windows IPC as a documented no-op

In `crates/guardrail-windows/src/lib.rs` or a small `ipc.rs`, explicitly document
that `IpcPolicy` is currently a no-op on Windows per `spec.md:123`. Do not
pretend to enforce strict IPC. If a future requirement appears, it should become
a separate plan.

**Verify**: `cargo doc --no-deps -p guardrail-windows` -> exit 0.

### Step 6: Add policy integration tests

Create `crates/guardrail-windows/tests/policy.rs` with `#![cfg(windows)]`.
Use the Windows probe from plan 010 if it already exists; otherwise create only
minimal tests here and let plan 010 expand them.

Required non-ignored tests once a probe exists:
- Default `NetworkPolicy::Deny` blocks outbound TCP connect.
- `NetworkPolicy::OutboundOnly` allows an outbound TCP connect to a local test
  listener or loopback target if AppContainer loopback is allowed for tests.
- `FsAccess::Read` allows reading a temp file only when the temp directory is
  granted.
- `FsAccess::Write` allows writing only under write-granted temp directories.
- A read grant must not allow writes.

If Windows AppContainer loopback restrictions make loopback network tests
unreliable, mark only the loopback-dependent tests ignored and document the
manual command to run them on a configured host.

**Verify**: `cargo test -p guardrail-windows --test policy` -> non-ignored tests
pass.

## Test plan

- Unit-test profile name creation and capability selection.
- Unit-test path-to-ACL plan construction where possible without mutating ACLs.
- Integration-test real file grants against a temporary directory.
- Integration-test network policy with a local listener if the host permits
  AppContainer loopback.

## Done criteria

- [ ] `NetworkPolicy::Deny` launches the child in an AppContainer with no
      internet capability.
- [ ] `FsAccess` grants are the only paths receiving temporary AppContainer ACEs.
- [ ] Original ACLs are restored when the child/guard is dropped.
- [ ] `IpcPolicy` is documented as Windows no-op, not falsely enforced.
- [ ] `cargo test -p guardrail-windows --test policy` exits 0 for non-ignored
      tests.
- [ ] `cargo test --workspace` exits 0.
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` exits 0.
- [ ] `cargo fmt --check` exits 0.
- [ ] `plans/README.md` row 009 is updated to DONE.

## STOP conditions

Stop and report if:
- The maintainer rejects temporary ACL changes for explicit `FsAccess` paths.
  A broker/temp-workspace design is then required instead.
- ACL restoration fails in tests even once; do not proceed with a backend that
  leaves host permissions widened.
- `NetworkPolicy::Full` cannot be represented distinctly from
  `OutboundOnly` using AppContainer capabilities.
- AppContainer launch requires unstable Rust standard-library APIs instead of
  raw `windows-sys` calls.

## Maintenance notes

The security review should focus on cleanup paths: every AppContainer profile,
allocated SID, attribute list, and temporary ACL change needs a clear owner and
`Drop` path. The AppContainer no-network behavior is the main Windows security
property; do not weaken it to make tests pass.
