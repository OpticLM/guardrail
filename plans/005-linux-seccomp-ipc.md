# Plan 005: Add seccomp-BPF IPC confinement to `guardrail-linux`

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving on. If
> anything in "STOP conditions" occurs, stop and report — do not improvise.
> When done, update the status row for this plan in `plans/README.md`.
>
> **Drift check (run first)**: `git diff --stat <SHA-from-Status>..HEAD -- crates/guardrail-linux/src/seccomp.rs`
> This plan extends the `seccomp.rs` module created by plan 004. If that file
> does not contain `build()` and `add_network_rules()` as described in "Current
> state", reconcile before proceeding; on a real mismatch, STOP.

## Status

- **Priority**: P2
- **Effort**: M
- **Risk**: MED (over-blocking IPC syscalls can break unrelated programs)
- **Depends on**: plans/001, plans/002, **plans/004** (extends its `seccomp.rs`).
  Independent of plan 003.
- **Category**: security (IPC confinement)
- **Planned at**: commit `a1d2a66`, 2026-06-21 (re-run drift check against the post-004 tree)

## Why this matters

`spec.md` §2 and §5.3: the sandbox must cut **inter-process communication** so
untrusted code cannot manipulate or snoop on other processes — no SysV shared
memory / message queues / semaphores, no POSIX message queues, and critically no
`ptrace`/`process_vm_*` (which would let sandboxed code read or hijack other
processes). This plan adds those denials to the **existing** seccomp filter from
plan 004 and wires the two IPC levels from `guardrail_core::IpcPolicy`:

- `Strict` (default): block SysV IPC, POSIX mqueue, and process inspection.
- `Relaxed`: permit shared memory and POSIX mqueue (per §5.3's "recommended"
  level that allows shared memory), but still block process inspection
  (`ptrace`, `process_vm_*`) — those are never benign for a sandbox.

`spec.md` §5.3 also says benign same-process primitives — **pipes, `socketpair`,
anonymous `mmap`** — must keep working. The denylist design guarantees this: we
never list those syscalls, so the default `Allow` covers them.

## Current state

After plan 004, `crates/guardrail-linux/src/seccomp.rs` contains:
- `const VIOLATION_ACTION: SeccompAction = SeccompAction::Trap;`
- `type RuleMap = BTreeMap<i64, Vec<SeccompRule>>;`
- `pub(crate) fn build(config: &SandboxConfig) -> Result<Option<BpfProgram>, Error>`
  which calls `add_network_rules(&mut rules, config.network)?` and has a comment
  placeholder: `// Plan 005 inserts: add_ipc_rules(&mut rules, config.ipc)?;`
- `fn add_network_rules(rules: &mut RuleMap, policy: NetworkPolicy)`
- `fn socket_domain_rule(family: libc::c_int) -> Result<SeccompRule, Error>`
- `pub(crate) fn apply(program: &BpfProgram)`

`guardrail_core` exposes (unchanged): `IpcPolicy::{Strict, Relaxed}` and
`SandboxConfig.ipc: IpcPolicy`.

The `guardrail-probe` binary handles (after 002/003/004): `echo-env`, `alloc`,
`spin`, `read-file`, `write-file`, `socket-inet`, `tcp-bind`. This plan adds
`shm` and `ptrace-self`.

### IPC syscalls to block (decided — follow exactly)

All added as **whole-syscall** rules (empty condition vec = match any args),
match action = the existing `VIOLATION_ACTION` (Trap/SIGSYS).

`Strict` blocks all of:
- **SysV shared memory**: `shmget`, `shmat`, `shmdt`, `shmctl`
- **SysV message queues**: `msgget`, `msgsnd`, `msgrcv`, `msgctl`
- **SysV semaphores**: `semget`, `semop`, `semtimedop`, `semctl`
- **POSIX message queues**: `mq_open`, `mq_unlink`, `mq_timedsend`,
  `mq_timedreceive`, `mq_notify`, `mq_getsetattr`
- **Process inspection**: `ptrace`, `process_vm_readv`, `process_vm_writev`

`Relaxed` blocks only:
- **Process inspection**: `ptrace`, `process_vm_readv`, `process_vm_writev`

> **Do NOT block**: `pipe`, `pipe2`, `socketpair`, `mmap`, `eventfd`,
> `eventfd2`, `memfd_create`, `futex`. These are benign/essential
> (`spec.md` §5.3) and must remain allowed under both levels. They are simply
> absent from the denylist.

> **`libc::SYS_*` availability**: every syscall above has a `libc::SYS_<name>`
> constant on x86_64/aarch64/riscv64. If any constant is missing on the target
> arch (some SysV calls are multiplexed via `ipc` on certain arches), see the
> STOP conditions — report rather than skipping a denial silently.

## Commands you will need

| Purpose          | Command                                                          | Expected   |
|------------------|------------------------------------------------------------------|------------|
| Build            | `cargo build -p guardrail-linux`                                 | exit 0     |
| Test (this plan) | `cargo test -p guardrail-linux --test ipc`                       | all pass   |
| Full crate test  | `cargo test -p guardrail-linux`                                  | all pass   |
| Lint             | `cargo clippy -p guardrail-linux --all-targets -- -D warnings`   | exit 0     |
| Format check     | `cargo fmt --check`                                              | exit 0     |

## Suggested executor toolkit

- Use the **`docs-rs` MCP** on crate `libc` to confirm the `SYS_*` constant
  names if any fail to compile (e.g. `SYS_semtimedop`, `SYS_mq_getsetattr`).

## Scope

**In scope** (modify/create only these):
- `crates/guardrail-linux/src/seccomp.rs` — add `add_ipc_rules` + a whole-syscall
  rule helper; call it from `build`
- `crates/guardrail-linux/src/bin/guardrail-probe.rs` — add `shm`, `ptrace-self`
- `crates/guardrail-linux/tests/ipc.rs` (create)
- `plans/README.md` (status update)

**Out of scope**:
- Network rules / `add_network_rules` — do not modify plan 004's network logic.
- The `VIOLATION_ACTION` constant and `apply`/`build` signatures — reuse as-is.
- `fs.rs`, `rlimit.rs`, `lib.rs` — the `pre_exec` wiring already installs the
  combined filter (plan 004). IPC rules ride along automatically once `build`
  adds them. You should **not** need to touch `lib.rs`.
- `guardrail-core` — `IpcPolicy` is fixed. STOP if you think it needs change.

## Version control

Repo uses **jj** colocated with git. **Do not commit/branch/push.** Leave changes
in the working copy.

## Steps

### Step 1: Add `add_ipc_rules` and a whole-syscall helper to `seccomp.rs`

Add to `crates/guardrail-linux/src/seccomp.rs`:

```rust
use guardrail_core::IpcPolicy; // add to the existing `use guardrail_core::{...}`

/// Syscalls blocked only at the `Strict` level (SysV IPC + POSIX mqueue).
const STRICT_ONLY_IPC: &[i64] = &[
    // SysV shared memory
    libc::SYS_shmget, libc::SYS_shmat, libc::SYS_shmdt, libc::SYS_shmctl,
    // SysV message queues
    libc::SYS_msgget, libc::SYS_msgsnd, libc::SYS_msgrcv, libc::SYS_msgctl,
    // SysV semaphores
    libc::SYS_semget, libc::SYS_semop, libc::SYS_semtimedop, libc::SYS_semctl,
    // POSIX message queues
    libc::SYS_mq_open, libc::SYS_mq_unlink, libc::SYS_mq_timedsend,
    libc::SYS_mq_timedreceive, libc::SYS_mq_notify, libc::SYS_mq_getsetattr,
];

/// Process-inspection syscalls blocked at BOTH levels. Never benign for a
/// sandbox: they let code read/modify other processes' memory.
const ALWAYS_BLOCKED_IPC: &[i64] = &[
    libc::SYS_ptrace, libc::SYS_process_vm_readv, libc::SYS_process_vm_writev,
];

fn add_ipc_rules(rules: &mut RuleMap, policy: IpcPolicy) -> Result<(), Error> {
    for &sys in ALWAYS_BLOCKED_IPC {
        rules.entry(sys).or_default(); // empty Vec = match any args
    }
    if policy == IpcPolicy::Strict {
        for &sys in STRICT_ONLY_IPC {
            rules.entry(sys).or_default();
        }
    }
    Ok(())
}
```

> Using `.entry(sys).or_default()` keeps any rules a previous step put on the
> same syscall (none overlap network here, but this is the safe idiom). An empty
> `Vec<SeccompRule>` means "match regardless of arguments" — same semantic plan
> 004 relies on for `bind`/`listen`.

Then, in `build`, replace the placeholder comment with the actual call:

```rust
    add_network_rules(&mut rules, config.network)?;
    add_ipc_rules(&mut rules, config.ipc)?;   // <-- this plan
```

> Because `Strict`/`Relaxed` always block at least the three process-inspection
> syscalls, `build` will now return `Some(_)` for the default config (it did so
> already once any network rule existed; now it's true even under
> `NetworkPolicy::Full + IpcPolicy::Relaxed`).

**Verify**:
- `cargo build -p guardrail-linux` → exit 0
- `cargo clippy -p guardrail-linux --lib -- -D warnings` → exit 0
- If any `libc::SYS_*` constant is undefined on this arch, see STOP conditions.

### Step 2: Add `shm` / `ptrace-self` commands to the probe

In `crates/guardrail-linux/src/bin/guardrail-probe.rs`, add:

- `"shm"`: try to create a SysV shared-memory segment; exit `0` on success,
  `3` on failure:
  ```rust
  "shm" => {
      // SAFETY: shmget with scalar args. IPC_PRIVATE creates a new segment.
      let id = unsafe { libc::shmget(libc::IPC_PRIVATE, 4096, libc::IPC_CREAT | 0o600) };
      if id < 0 {
          exit(3);
      }
      // Best-effort cleanup; ignore errors.
      unsafe { libc::shmctl(id, libc::IPC_RMID, std::ptr::null_mut()) };
      exit(0);
  }
  ```
- `"ptrace-self"`: try `ptrace(PTRACE_TRACEME)`; exit `0` on success, `3` on
  failure:
  ```rust
  "ptrace-self" => {
      // SAFETY: ptrace TRACEME takes no pointer args.
      let rc = unsafe { libc::ptrace(libc::PTRACE_TRACEME, 0, std::ptr::null_mut::<libc::c_void>(), std::ptr::null_mut::<libc::c_void>()) };
      if rc < 0 { exit(3); } else { exit(0); }
  }
  ```
  (`ptrace`'s variadic signature varies; if the 4-arg form doesn't compile,
  check `libc::ptrace` on docs.rs for the exact arity on this target.)

Update the usage string and doc comment.

> Under the sandbox, `shm` (Strict) and `ptrace-self` (both levels) are killed
> by **SIGSYS**, so the child dies by signal — tests assert "not success".

**Verify**: `cargo build -p guardrail-linux --bin guardrail-probe` → exit 0.

### Step 3: Integration tests — `ipc.rs`

Create `crates/guardrail-linux/tests/ipc.rs`. Validate intent (spec §7):

```rust
use std::process::{Command, Stdio};

use guardrail_core::{IpcPolicy, SandboxBuilder, SandboxConfig};
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

fn base() -> SandboxBuilder {
    let exe = std::path::PathBuf::from(env!("CARGO_BIN_EXE_guardrail-probe"));
    SandboxBuilder::new().allow_read(exe.parent().unwrap().to_path_buf())
}

#[test]
fn strict_blocks_shared_memory() {
    let config = base().ipc(IpcPolicy::Strict).build();
    assert!(
        !allowed(&config, &["shm"]),
        "SysV shared memory must be blocked under Strict IPC"
    );
}

#[test]
fn relaxed_allows_shared_memory() {
    let config = base().ipc(IpcPolicy::Relaxed).build();
    assert!(
        allowed(&config, &["shm"]),
        "shared memory must be allowed under Relaxed IPC"
    );
}

#[test]
fn ptrace_is_blocked_at_both_levels() {
    for level in [IpcPolicy::Strict, IpcPolicy::Relaxed] {
        let config = base().ipc(level).build();
        assert!(
            !allowed(&config, &["ptrace-self"]),
            "ptrace must be blocked under {level:?} IPC"
        );
    }
}

#[test]
fn default_ipc_is_strict() {
    // The builder default must be Strict (matches guardrail-core's default).
    let config = base().build();
    assert!(
        !allowed(&config, &["shm"]),
        "default IPC level must behave as Strict (shm blocked)"
    );
}
```

**Verify**:
- `cargo test -p guardrail-linux --test ipc` → all 4 pass
- `cargo test -p guardrail-linux` → all suites still pass (network rules from
  plan 004 unaffected)

## Test plan

- `ipc.rs` asserts: `Strict` blocks shared memory; `Relaxed` allows it;
  `ptrace` blocked at *both* levels; the builder default behaves as `Strict`.
  Intent-level, using the deterministic `guardrail-probe`.
- A regression guard for plan 004: running the full `cargo test -p guardrail-linux`
  confirms the network tests still pass after IPC rules join the same filter.
- Model after `tests/network.rs`.

## Done criteria

Machine-checkable. ALL must hold:

- [ ] `cargo build -p guardrail-linux` exits 0
- [ ] `cargo test -p guardrail-linux --test ipc` exits 0 (4 tests pass)
- [ ] `cargo test -p guardrail-linux --test network` still exits 0 (no regression)
- [ ] `cargo test -p guardrail-linux` exits 0 (all suites)
- [ ] `cargo clippy -p guardrail-linux --all-targets -- -D warnings` exits 0
- [ ] `cargo fmt --check` exits 0
- [ ] `lib.rs` was NOT modified (`git diff --quiet -- crates/guardrail-linux/src/lib.rs`)
- [ ] `guardrail-core` unchanged
- [ ] No files outside the in-scope list are modified
- [ ] `plans/README.md` status row for 005 set to DONE

## STOP conditions

Stop and report (do not improvise) if:

- Any `libc::SYS_*` constant in `STRICT_ONLY_IPC`/`ALWAYS_BLOCKED_IPC` does not
  exist on this target arch. **Do not silently drop the syscall** — a missing
  denial is a security hole. Report the arch and the missing constant so the
  list can be made arch-aware.
- `relaxed_allows_shared_memory` fails — that means `Relaxed` is incorrectly
  blocking `shm*`; check that `STRICT_ONLY_IPC` is gated behind
  `policy == IpcPolicy::Strict`.
- Any `tests/network.rs` test regresses — IPC rules must not perturb network
  rules; if they do, you likely edited `add_network_rules` (out of scope).
- `seccomp.rs` from plan 004 isn't shaped as "Current state" describes (drift).
- `ptrace-self` / `shm` probe commands fail to compile due to `libc` signature
  differences and docs.rs doesn't clarify the correct arity.

## Maintenance notes

- **`Relaxed` deliberately still blocks `ptrace`/`process_vm_*`.** These let a
  process read/write another's memory and are never appropriate inside a
  sandbox, regardless of the IPC level. A reviewer should reject any change that
  moves them out of `ALWAYS_BLOCKED_IPC`.
- **The benign-primitives allowlist is implicit** (by omission): `pipe`,
  `socketpair`, `mmap`, `eventfd`, `futex`, `memfd_create` are never listed, so
  they stay allowed (`spec.md` §5.3). If a future change converts the filter to
  an allowlist, those must be explicitly permitted or normal programs break.
- **Arch-specific SysV multiplexing**: on some architectures SysV IPC is reached
  via a single `ipc` syscall rather than individual `shmget`/`msgget`/etc. This
  plan targets arches with discrete syscalls (x86_64/aarch64/riscv64). If the
  project later supports such an arch, the list needs an `ipc`-multiplexer branch.
- The combined filter (network + IPC) is built once per spawn in `seccomp::build`
  and applied last in `pre_exec`; plan 006 reads the resulting SIGSYS on the
  parent side to produce diagnostics.
</content>
