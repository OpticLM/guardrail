# Plan 004: Add seccomp-BPF network confinement to `guardrail-linux`

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving on. If
> anything in "STOP conditions" occurs, stop and report — do not improvise.
> When done, update the status row for this plan in `plans/README.md`.
>
> **Drift check (run first)**: `git diff --stat <SHA-from-Status>..HEAD -- crates/guardrail-linux/src/lib.rs`
> This plan adds a step at the `pre_exec` INSERTION POINT created in plan 002.
> If that point is gone, reconcile before proceeding; on a real mismatch, STOP.

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: MED (a seccomp filter that's too broad breaks normal programs)
- **Depends on**: plans/001, plans/002. **Independent of plan 003** (can land
  before or after Landlock). **Plan 005 (IPC) extends the module this plan
  creates**, so 004 lands before 005.
- **Category**: security (network confinement)
- **Planned at**: commit `a1d2a66`, 2026-06-21 (re-run drift check against the post-002 tree)

## Why this matters

`spec.md` §2 and §5.2: by default the sandbox must be **disconnected from the
network** to prevent reverse shells and payload downloads. §4.1 assigns this to
**seccomp-BPF** ("used to implement network-level policies that Landlock alone
cannot handle"). This plan builds the seccomp filter and wires the three network
levels from `guardrail_core::NetworkPolicy`:

- `Deny` (default): cannot create IP sockets at all.
- `OutboundOnly`: can create IP sockets and `connect`, but cannot `bind`/`listen`.
- `Full`: no network syscalls filtered.

It creates the shared `seccomp.rs` module (filter assembly + application) that
**plan 005 extends** with IPC rules into the *same* filter.

## Current state

After plan 002 (and possibly 003), `crates/guardrail-linux/src/lib.rs`'s
`pre_exec` closure ends with the documented INSERTION POINT. Plan 002's comment
states seccomp is applied **last**:

```rust
                // (3) INSERTION POINT — later plans add, in this order:
                //       fs::apply(&fs_rules)?;        // plan 003 (Landlock)
                //       seccomp::apply(&filter)?;     // plans 004/005 (last)
                //     Apply seccomp LAST so its filter does not interfere with
                //     Landlock's own setup syscalls.
```

`guardrail_core` exposes (unchanged): `NetworkPolicy::{Deny, OutboundOnly, Full}`
and `SandboxConfig.network: NetworkPolicy`. `IpcPolicy` also exists but is plan
005's concern — this plan must structure `seccomp.rs` so 005 can add IPC rules
without rewriting it.

The `guardrail-probe` binary handles `echo-env`, `alloc`, `spin`, and (if 003
landed) `read-file`/`write-file`. This plan adds `socket-inet`, `tcp-bind`.

### seccomp design (decided — follow exactly)

**The filter is a denylist**: default action **Allow** (so arbitrary shell tools
keep working), with specific syscalls/arguments mapped to a **single match
action `SeccompAction::Trap`** (sends `SIGSYS`, terminating the child). Trap is
chosen over `Errno` so that **plan 006 can observe the violation from the parent**
(the child dies with `WTERMSIG == SIGSYS`) and name the policy to add — satisfying
`spec.md` §6. Centralize the action in one constant so switching to graceful
`Errno` later is a one-line change.

**Key seccomp fact**: seccomp can inspect syscall *scalar arguments* but **cannot
dereference pointers**. So:
- `socket(domain, type, protocol)` — `domain` is arg 0, a scalar. We **can**
  filter on address family. Block creating `AF_INET`/`AF_INET6` sockets to cut
  IP networking at the source.
- `connect`/`bind`/`listen` take an `fd` (opaque scalar) — we cannot tell an IP
  socket from a Unix socket at these calls. So we gate IP networking at
  `socket()` creation, and only use whole-syscall blocks for `bind`/`listen`.

Per-level rules (x86_64/aarch64/riscv64 — direct socket syscalls, **not** the
i386 `socketcall` multiplexer):

| Policy         | Rules added (match → Trap)                                              |
|----------------|------------------------------------------------------------------------|
| `Deny`         | `socket` where `arg0 == AF_INET`; `socket` where `arg0 == AF_INET6`    |
| `OutboundOnly` | `bind` (any args); `listen` (any args)                                 |
| `Full`         | (none)                                                                  |

Notes:
- `AF_INET = 2`, `AF_INET6 = 10` (Linux, all listed arches). Use
  `libc::AF_INET`/`libc::AF_INET6` cast to `u64`.
- Under `Deny`, with no IP socket creatable, `connect`/`bind`/`listen` on IP are
  moot; `AF_UNIX` sockets (IPC) remain usable. We intentionally do **not** block
  `AF_UNIX`/`AF_NETLINK` (libc internals like NSS use netlink).
- Under `OutboundOnly`, blocking `bind` also blocks binding `AF_UNIX` sockets.
  That's acceptable for the outbound-HTTP use case; note it in maintenance.
- The spec's "(Windows-only) allow loopback" level is a no-op on Linux —
  `NetworkPolicy` has no such variant, so nothing to do.

### `seccompiler` API you will use (v0.5.x — verified)

```rust
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition,
    SeccompFilter, SeccompRule,
};
use std::convert::TryInto;

// rules: BTreeMap<i64, Vec<SeccompRule>>  (syscall number -> OR-bound rules)
// An empty Vec for a syscall means "match regardless of arguments".
let filter: BpfProgram = SeccompFilter::new(
    rules,
    SeccompAction::Allow,            // mismatch (default) action
    SeccompAction::Trap,             // match action
    std::env::consts::ARCH.try_into().unwrap(),  // TargetArch from arch string
)
.unwrap()
.try_into()
.unwrap();

seccompiler::apply_filter(&filter).unwrap();   // installs on current thread
```

- `SeccompCondition::new(arg_index, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, value_u64)`
  — `arg_index = 0` for `socket` domain; `Dword` because `domain` is a 32-bit int.
- A `SeccompRule::new(vec![cond, ...])` ANDs its conditions; multiple rules for
  one syscall are OR-bound. So `socket(AF_INET)` and `socket(AF_INET6)` are two
  separate rules under key `libc::SYS_socket`.
- `apply_filter` installs on the calling thread and requires `NO_NEW_PRIVS`
  (already set in plan 002's `pre_exec`).

## Commands you will need

| Purpose          | Command                                                          | Expected   |
|------------------|------------------------------------------------------------------|------------|
| Build            | `cargo build -p guardrail-linux`                                 | exit 0     |
| Test (this plan) | `cargo test -p guardrail-linux --test network`                   | all pass   |
| Full crate test  | `cargo test -p guardrail-linux`                                  | all pass   |
| Lint             | `cargo clippy -p guardrail-linux --all-targets -- -D warnings`   | exit 0     |
| Format check     | `cargo fmt --check`                                              | exit 0     |

## Suggested executor toolkit

- Use the **`docs-rs` MCP** on crate `seccompiler` for `SeccompFilter`,
  `SeccompCondition`, `SeccompCmpArgLen`, `SeccompCmpOp`, `SeccompAction`,
  `apply_filter`, and the `TryInto<TargetArch>` for the arch string — confirm
  exact variant names before writing.

## Scope

**In scope** (create/modify only these):
- `Cargo.toml` (root) — add `seccompiler` to `[workspace.dependencies]`
- `crates/guardrail-linux/Cargo.toml` — depend on `seccompiler`
- `crates/guardrail-linux/src/seccomp.rs` (create — filter assembly + apply;
  **structured so plan 005 adds IPC rules**)
- `crates/guardrail-linux/src/lib.rs` — declare `mod seccomp;`, apply the filter
  at the insertion point (after `fs::apply` if present)
- `crates/guardrail-linux/src/bin/guardrail-probe.rs` — add `socket-inet`,
  `tcp-bind`
- `crates/guardrail-linux/tests/network.rs` (create)
- `plans/README.md` (status update)

**Out of scope**:
- IPC syscalls (shm/msg/sem/mqueue/ptrace) — plan 005. Structure the module for
  it, but do **not** add IPC rules here.
- Landlock / `fs.rs` — leave plan 003's code alone.
- `guardrail-core` — `NetworkPolicy` is fixed. STOP if you think it needs change.

## Version control

Repo uses **jj** colocated with git. **Do not commit/branch/push.** Leave changes
in the working copy.

## Steps

### Step 1: Add the `seccompiler` dependency

- Root `Cargo.toml` `[workspace.dependencies]`: add `seccompiler = "0.5"`.
- `crates/guardrail-linux/Cargo.toml` `[dependencies]`: add `seccompiler.workspace = true`.

**Verify**: `cargo build -p guardrail-linux` → exit 0 (resolves `seccompiler` 0.5.x).

### Step 2: Implement `seccomp.rs` — filter assembly (network) + apply

Create `crates/guardrail-linux/src/seccomp.rs`. Design it as a **rule collector**
so plan 005 can add IPC rules to the same map:

- A single centralized match action constant:
  `const VIOLATION_ACTION: SeccompAction = SeccompAction::Trap;`
- `pub(crate) fn build(config: &SandboxConfig) -> Result<Option<BpfProgram>, Error>`:
  - Start an empty `BTreeMap<i64, Vec<SeccompRule>>`.
  - Call `add_network_rules(&mut rules, config.network)?`.
  - (Plan 005 will add `add_ipc_rules(&mut rules, config.ipc)?` here.)
  - If the map is empty, return `Ok(None)` (nothing to enforce).
  - Otherwise compile with `SeccompFilter::new(rules, Allow, VIOLATION_ACTION, arch)`
    → `BpfProgram`, wrapping errors in `Error::confinement("seccomp", e)`.
- `pub(crate) fn apply(program: &BpfProgram) -> Result<(), Error>` calling
  `seccompiler::apply_filter(program)`, wrapping errors.
- A private helper to make a `socket(domain == X)` rule.

Target shape:

```rust
//! Network and IPC confinement via a seccomp-BPF denylist.
//!
//! Default action is Allow (arbitrary shell tools must keep working); specific
//! syscalls/arguments are mapped to `VIOLATION_ACTION`. Trap is used so a
//! violation terminates the child with SIGSYS, which the parent can observe
//! (see plan 006). Network rules live here; IPC rules are added by plan 005 to
//! the same filter via `add_ipc_rules`.

use std::collections::BTreeMap;
use std::convert::TryInto;

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition,
    SeccompFilter, SeccompRule,
};

use guardrail_core::{Error, NetworkPolicy, SandboxConfig};

/// Action taken when a denied syscall is attempted. Trap → SIGSYS (observable
/// by the parent). Change to `SeccompAction::Errno(libc::EACCES as u32)` for
/// graceful per-call failure instead of process termination.
const VIOLATION_ACTION: SeccompAction = SeccompAction::Trap;

type RuleMap = BTreeMap<i64, Vec<SeccompRule>>;

/// Build the combined seccomp filter for `config`. Returns `Ok(None)` when no
/// rules apply (e.g. NetworkPolicy::Full and — once plan 005 lands — a no-op IPC
/// level), meaning the caller should skip installation.
pub(crate) fn build(config: &SandboxConfig) -> Result<Option<BpfProgram>, Error> {
    let mut rules: RuleMap = BTreeMap::new();
    add_network_rules(&mut rules, config.network)?;
    // Plan 005 inserts: add_ipc_rules(&mut rules, config.ipc)?;

    if rules.is_empty() {
        return Ok(None);
    }

    let arch = std::env::consts::ARCH
        .try_into()
        .map_err(|e| Error::confinement("seccomp", e))?;
    let filter = SeccompFilter::new(rules, SeccompAction::Allow, VIOLATION_ACTION, arch)
        .map_err(|e| Error::confinement("seccomp", e))?;
    let program: BpfProgram = filter
        .try_into()
        .map_err(|e| Error::confinement("seccomp", e))?;
    Ok(Some(program))
}

/// Install `program` on the current thread. Requires NO_NEW_PRIVS (set earlier
/// in pre_exec). Async-signal-safe enough for pre_exec (a prctl wrapper).
pub(crate) fn apply(program: &BpfProgram) -> Result<(), Error> {
    seccompiler::apply_filter(program).map_err(|e| Error::confinement("seccomp", e))
}

fn add_network_rules(rules: &mut RuleMap, policy: NetworkPolicy) -> Result<(), Error> {
    match policy {
        NetworkPolicy::Deny => {
            // Block creation of IP sockets at the source.
            rules
                .entry(libc::SYS_socket)
                .or_default()
                .push(socket_domain_rule(libc::AF_INET)?);
            rules
                .entry(libc::SYS_socket)
                .or_default()
                .push(socket_domain_rule(libc::AF_INET6)?);
        }
        NetworkPolicy::OutboundOnly => {
            // IP sockets allowed; binding/listening denied (any args).
            rules.entry(libc::SYS_bind).or_default(); // empty Vec = match all args
            rules.entry(libc::SYS_listen).or_default();
        }
        NetworkPolicy::Full => {}
    }
    Ok(())
}

/// A rule matching `socket(domain == family, ..)`.
fn socket_domain_rule(family: libc::c_int) -> Result<SeccompRule, Error> {
    let cond = SeccompCondition::new(
        0, // arg0 = domain
        SeccompCmpArgLen::Dword,
        SeccompCmpOp::Eq,
        family as u64,
    )
    .map_err(|e| Error::confinement("seccomp", e))?;
    SeccompRule::new(vec![cond]).map_err(|e| Error::confinement("seccomp", e))
}
```

> **`.or_default()` then nothing** gives an empty `Vec<SeccompRule>` for `bind`/
> `listen` — seccompiler treats that as "match this syscall regardless of args".
> Confirm that semantic on docs.rs (the README states it explicitly).
>
> If `SeccompFilter::new`/`try_into`'s error types don't implement
> `std::error::Error + Send + Sync + 'static` (needed by `Error::confinement`),
> map them via `Error::Unsupported(format!("seccomp: {e}"))` instead. Check the
> error type on docs.rs.

**Verify**: deferred to Step 3 (needs `mod seccomp;`).

### Step 3: Wire seccomp into `pre_exec` (applied LAST)

In `crates/guardrail-linux/src/lib.rs`:
- Add `mod seccomp;`.
- **Before** the `unsafe` block, build the program in the parent (allocation is
  fine there) so the child closure only calls `apply_filter`:
  ```rust
  let seccomp_program = seccomp::build(config)?;
  ```
- Move it into the closure and, at the INSERTION POINT **after** `fs::apply`
  (if present), add:
  ```rust
  if let Some(program) = &seccomp_program {
      seccomp::apply(program)?;
  }
  ```
  Update the comment so seccomp is clearly the last confinement step.

> Building the BPF program in the parent and only calling `apply_filter` in the
> child keeps post-fork work minimal (just a `prctl`).

**Verify**:
- `cargo build -p guardrail-linux` → exit 0
- `cargo clippy -p guardrail-linux --lib -- -D warnings` → exit 0

### Step 4: Add `socket-inet` / `tcp-bind` to the probe

In `crates/guardrail-linux/src/bin/guardrail-probe.rs`, add:

- `"socket-inet"`: try to create an `AF_INET` TCP socket; exit `0` if created,
  `3` if it fails. Use `std::net` indirectly or `libc::socket`:
  ```rust
  "socket-inet" => {
      // SAFETY: socket() with scalar args; close the fd if created.
      let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
      if fd < 0 {
          exit(3);
      }
      unsafe { libc::close(fd) };
      exit(0);
  }
  ```
  (Add `libc` as a normal dependency of the bin — it already is, since the crate
  depends on `libc`. The bin shares the crate's deps.)
- `"tcp-bind"`: try to bind a TCP listener on `127.0.0.1:0`; exit `0` on success,
  `3` on failure:
  ```rust
  "tcp-bind" => {
      match std::net::TcpListener::bind(("127.0.0.1", 0)) {
          Ok(_) => exit(0),
          Err(_) => exit(3),
      }
  }
  ```
Update the usage string and doc comment.

> Note: under `Deny`, `socket-inet` is killed by **SIGSYS** (Trap), so the child
> exits via signal, not code 3. Tests below assert "not success", which covers
> both signal-death and code 3.

**Verify**: `cargo build -p guardrail-linux --bin guardrail-probe` → exit 0.

### Step 5: Integration tests — `network.rs`

Create `crates/guardrail-linux/tests/network.rs`. Validate intent (spec §7):

```rust
use std::process::{Command, Stdio};

use guardrail_core::{NetworkPolicy, SandboxBuilder, SandboxConfig};
use guardrail_linux::LinuxBackend;

fn probe(args: &[&str]) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_guardrail-probe"));
    c.args(args).stdout(Stdio::null()).stderr(Stdio::null());
    c
}

fn allowed(config: &SandboxConfig, args: &[&str]) -> bool {
    let mut child = config
        .spawn_with(&LinuxBackend::new(), probe(args))
        .expect("spawn");
    child.wait().expect("wait").success()
}

/// Grant read on the binary's dir so it loads under any Landlock rules that may
/// also be active; network tests should not be coupled to FS confinement.
fn base() -> SandboxBuilder {
    let exe = std::path::PathBuf::from(env!("CARGO_BIN_EXE_guardrail-probe"));
    SandboxBuilder::new().allow_read(exe.parent().unwrap().to_path_buf())
}

#[test]
fn deny_blocks_inet_socket_creation() {
    let config = base().network(NetworkPolicy::Deny).build();
    assert!(
        !allowed(&config, &["socket-inet"]),
        "creating an AF_INET socket must be blocked under Deny"
    );
}

#[test]
fn outbound_only_allows_socket_but_blocks_bind() {
    let config = base().network(NetworkPolicy::OutboundOnly).build();
    assert!(
        allowed(&config, &["socket-inet"]),
        "AF_INET socket creation must be allowed under OutboundOnly"
    );
    assert!(
        !allowed(&config, &["tcp-bind"]),
        "binding/listening must be blocked under OutboundOnly"
    );
}

#[test]
fn full_allows_socket_and_bind() {
    let config = base().network(NetworkPolicy::Full).build();
    assert!(
        allowed(&config, &["socket-inet"]),
        "socket creation must be allowed under Full"
    );
    assert!(
        allowed(&config, &["tcp-bind"]),
        "binding must be allowed under Full"
    );
}
```

**Verify**:
- `cargo test -p guardrail-linux --test network` → all 3 pass
- `cargo test -p guardrail-linux` → everything still passes

## Test plan

- `network.rs` asserts the discriminating behavior of each level: `Deny` blocks
  socket creation; `OutboundOnly` allows the socket but blocks `bind`; `Full`
  allows both. These are the intent-level guarantees, not syscall-by-syscall
  mirrors.
- Uses the `guardrail-probe` helper (no network connectivity required — socket
  *creation* and local `bind` are the discriminators, so tests pass offline/CI).
- Model after `tests/resource_limits.rs` / `tests/filesystem.rs`.

## Done criteria

Machine-checkable. ALL must hold:

- [ ] `cargo build -p guardrail-linux` exits 0 (with `seccompiler` resolved)
- [ ] `cargo test -p guardrail-linux --test network` exits 0 (3 tests pass)
- [ ] `cargo test -p guardrail-linux` exits 0 (all suites)
- [ ] `cargo clippy -p guardrail-linux --all-targets -- -D warnings` exits 0
- [ ] `cargo fmt --check` exits 0
- [ ] `seccomp.rs` exposes `build(&SandboxConfig)` and a private
      `add_network_rules` (so plan 005 can add `add_ipc_rules` to the same map)
- [ ] `guardrail-core` unchanged; no IPC syscalls referenced yet
- [ ] No files outside the in-scope list are modified
- [ ] `plans/README.md` status row for 004 set to DONE

## STOP conditions

Stop and report (do not improvise) if:

- `full_allows_socket_and_bind` fails — that means the default-Allow denylist is
  wrong (it should filter *nothing* under `Full`); a failure here means the
  filter is over-broad. Report, don't widen blindly.
- `deny_blocks_inet_socket_creation` passes but you observe the child dying for
  an unrelated reason (e.g. it can't even start). Re-run with stdio inherited to
  see why; report if the cause isn't the socket block.
- `apply_filter` returns EACCES/EINVAL — usually `NO_NEW_PRIVS` wasn't set
  (plan 002 should have). Confirm plan 002's `set_no_new_privs()` still runs
  first; report if so and it still fails.
- The host arch is not x86_64/aarch64/riscv64 (e.g. 32-bit i386 uses the
  `socketcall` multiplexer this plan does not handle). Report the arch.
- `seccompiler`'s API differs from this plan and docs.rs doesn't reconcile it.

## Maintenance notes

- **Denylist, default-Allow** is deliberate: an allowlist would have to enumerate
  every syscall arbitrary shell tools use and would break constantly. The cost is
  that only the explicitly-listed syscalls are confined.
- **`OutboundOnly` blocks ALL `bind`**, including `AF_UNIX` bind. Fine for the
  outbound-HTTP use case; revisit if a workload needs Unix-socket servers while
  outbound IP is allowed.
- **Arch coverage**: x86_64/aarch64/riscv64 only (direct socket syscalls). 32-bit
  x86's `socketcall` would need separate handling — out of scope.
- **`VIOLATION_ACTION` is centralized**: switching from `Trap` (SIGSYS, parent-
  observable) to `Errno` (graceful) is a one-line change. Plan 006's diagnostics
  assume `Trap`; if you change it, update plan 006's signal mapping too.
- **Plan 005 will add IPC rules to this same filter** via `add_ipc_rules`. A
  reviewer of 005 should confirm it only *adds* keys and does not alter the
  network rules or the match action.
</content>
