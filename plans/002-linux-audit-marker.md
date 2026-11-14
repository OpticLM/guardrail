# Plan 002: Every Linux sandbox process carries a marker the kernel audit trail can filter on

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md` — unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**: `git diff --stat a5c8219..HEAD -- crates/guardrail-linux crates/guardrail-napi/README.md`
> If any in-scope file changed since this plan was written, compare the
> "Current state" excerpts against the live code before proceeding; on a
> mismatch, treat it as a STOP condition.

## Status

- **Priority**: P1
- **Effort**: S
- **Risk**: LOW
- **Depends on**: none
- **Category**: direction
- **Planned at**: commit `a5c8219`, 2026-11-14

## Why this matters

Guardrail sandboxes LLM agents, and operators need to see when an agent hit a
sandbox rule. The design decision is that guardrail does **not** collect or
expose logs; it only leaves markers in the operating system's own logs, and
operators retrieve those with their own tools.

On Linux the hard case is denials that Landlock does not make. A deny rule
beneath an allowed parent (for example `WriteDeny(project/.git)` under
`WriteAllow(project)`) is enforced by a mount mask: a read-only or empty
mount placed over the path. The kernel sees those as ordinary `EROFS` /
`EACCES` errors from the filesystem layer. Landlock allowed the access, so
Landlock's audit log never mentions them — yet these are exactly the
deliberate rules whose violations operators most want to count.

The Linux audit subsystem can already log any failed syscall, with the path
the process used. What is missing is a way to select guardrail's processes.
This plan adds that: one `personality(2)` call marks the sandboxed process
tree with a value that (a) is inherited by every descendant across `fork` and
`execve`, (b) is printed as `per=` in every syscall audit record, and (c) can
be matched by an audit rule (`-F pers`). Nothing is logged unless the host's
administrator installs audit rules, so there is no noise and no config
switch.

Facts verified while writing this plan (do not re-derive, but do not
contradict):

- `personality(2)` flags `SHORT_INODE` (`0x1000000`) and `WHOLE_SECONDS`
  (`0x2000000`) are documented as "No effect" in the man page, and in kernel
  v6.18 they are referenced nowhere except their definition in
  `include/uapi/linux/personality.h`. They are not in `PER_CLEAR_ON_SETID`.
- On kernel 6.18, a process that set `0x3000000` showed `03000000` in
  `/proc/self/personality` in its child and grandchild after `execve`, and
  `uname`, `date`, `ls`, and Python `select` behaved normally.
- `kernel/auditsc.c` prints ` per=%lx` in the SYSCALL record whenever the
  personality is not `PER_LINUX`, and `kernel/auditfilter.c` accepts every
  comparison operator (including bit tests) for the `pers` rule field.
- The marker does **not** cover syscalls refused by seccomp (socket families,
  kernel-surface syscalls): the kernel runs seccomp before the audit entry
  hook, so those never produce a syscall audit record. Plan 003 covers them.

## Current state

- `crates/guardrail-linux/src/backend.rs` — builds the `pre_exec` closure that
  applies confinement in the forked child.
- `crates/guardrail-linux/src/bin/guardrail-probe.rs` — deterministic test
  helper; exits `0` (allowed), `3` (denied), `2` (usage error).
- `crates/guardrail-linux/tests/` — integration tests that spawn the probe.
- `crates/guardrail-linux/src/lib.rs` — crate docs.
- `crates/guardrail-napi/README.md` — user documentation.

`crates/guardrail-linux/src/backend.rs:82-94` (start of the `pre_exec`
closure):

```rust
            command.pre_exec(move || {
                // (1) NO_NEW_PRIVS first: required for Landlock and seccomp
                //     below, and a hardening measure on its own. prctl is
                //     async-signal-safe.
                set_no_new_privs()?;

                // (2) Enter fresh IPC/user/mount namespaces, mount private
                //     /dev/mqueue and /dev/shm filesystems, and install any
                //     deny-under-allow mount masks. This must precede
                //     Landlock, which denies mount-topology changes once
                //     enforced. The forked child is single-threaded, as
                //     unshare(CLONE_NEWUSER) requires.
                namespace.enter()?;
```

`crates/guardrail-linux/src/backend.rs:142-150` (the helper style to match):

```rust
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

The closure runs after `fork` in a possibly multithreaded parent, so it may
only make raw syscalls: no allocation, no locks, no formatting.

Probe command style, `crates/guardrail-linux/src/bin/guardrail-probe.rs:920-924`:

```rust
        "unshare-user" => {
            // SAFETY: unshare takes only a scalar flags argument.
            let rc = unsafe { libc::unshare(libc::CLONE_NEWUSER) };
            if rc == 0 { exit(0) } else { exit(3) }
        }
```

Each command is also listed in the `//!` header at the top of the probe file
and in the usage string in the final `_ =>` arm.

Integration test style, `crates/guardrail-linux/tests/kernel_surface.rs:16-23`
and `:84-92`:

```rust
fn status(config: &SandboxConfig, args: &[&str]) -> ExitStatus {
    let cmd = probe(args);
    let mut child = LinuxBackend::new(config.clone())
        .expect("backend")
        .spawn(cmd)
        .expect("spawn");
    child.wait().expect("wait")
}
```

```rust
#[test]
fn user_namespace_creation_is_denied_gracefully_by_default() {
    assert_eq!(
        status(&common::base(), &["unshare-user"]).code(),
        Some(3),
        "unshare(CLONE_NEWUSER) must fail with an errno under the default policy"
    );
}
```

`common::base()` and `common::probe(&[…])` live in
`crates/guardrail-linux/tests/common/mod.rs`.

Library facts (libc 0.2.186, the version in `Cargo.lock`):
`pub fn personality(persona: c_ulong) -> c_int`; passing `0xffffffff` returns
the current value without changing it.

Repo conventions that apply:

- KISS — no config field, no new public API, no log reading.
- Workspace clippy lints (root `Cargo.toml`) warn on `cast_sign_loss`,
  `undocumented_unsafe_blocks`, `multiple_unsafe_ops_per_block`,
  `unwrap_used`, `panic`. Every `unsafe` block needs its own `// SAFETY:`
  comment and exactly one unsafe operation; convert integers with `try_from`,
  not `as`.
- Commit messages use scoped-commits form, e.g.
  `linux: make policy paths durable against sandbox-staged decoys`.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Linux backend tests | `cargo test -p guardrail-linux --all-targets` | all pass |
| Default workspace tests | `cargo test --all-targets` | all pass |
| Doc tests | `cargo test --doc` | all pass |

**Host requirement.** The Linux backend needs unprivileged user + mount + IPC
namespaces. On the cloud container where this plan was written, the baseline
fails with `Unsupported("the Linux backend requires a fresh IPC namespace …
creating them failed: No such file or directory")`, so the suite could not be
confirmed green there. Run this plan on a host where the baseline passes
(CI uses `ubuntu-latest` after
`sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`).

## Scope

**In scope** (the only files you should modify):
- `crates/guardrail-linux/src/backend.rs`
- `crates/guardrail-linux/src/bin/guardrail-probe.rs`
- `crates/guardrail-linux/tests/audit_marker.rs` (create)
- `crates/guardrail-linux/src/lib.rs` (docs only)
- `crates/guardrail-napi/README.md` (docs only)

**Out of scope** (do NOT touch):
- `crates/guardrail-core` — no config field. The marker is always on because
  it logs nothing by itself.
- Landlock or seccomp logging flags — that is plan 003.
- Any code that reads audit logs, or that installs audit rules.
- A seccomp rule to stop the child from changing its own personality: the
  marker is for accidents and statistics, not a security boundary, and such a
  rule would break tools like `setarch`.
- macOS and Windows crates.

## Git workflow

- This repo uses jj colocated with git. If a `.jj` directory exists, use
  `jj describe -m "…"`; otherwise use git on a branch named
  `advisor/002-linux-audit-marker`.
- One commit. Message: `linux: mark sandboxed process trees for host auditing`.
- Do NOT push or open a PR unless the operator instructed it.

## Steps

### Step 1: Record the baseline

Run `cargo test -p guardrail-linux --all-targets`.

**Verify**: all tests pass; note the counts. If the suite fails with
`Unsupported(…namespace…)`, STOP — this host cannot run the backend.

### Step 2: Add the marker

In `crates/guardrail-linux/src/backend.rs`, add next to `set_no_new_privs`:

```rust
/// Audit marker for the sandboxed process tree: `SHORT_INODE |
/// WHOLE_SECONDS`, two `personality(2)` flags the kernel defines but never
/// reads. The value is inherited across `fork` and `execve`, printed as
/// `per=` in every syscall audit record, and matchable by an audit rule
/// (`-F pers`), so a host administrator can select guardrail's processes.
const AUDIT_PERSONALITY_MARKER: libc::c_ulong = 0x0300_0000;

/// Set [`AUDIT_PERSONALITY_MARKER`] on the calling process, keeping its other
/// personality bits. Best-effort: an ambient seccomp filter (systemd
/// `LockPersonality=`, a container runtime) may refuse `personality(2)`, and a
/// missing marker must never stop a spawn. Async-signal-safe.
fn mark_for_audit() {
    // SAFETY: personality takes one scalar argument; 0xffffffff only queries.
    let current = unsafe { libc::personality(0xffff_ffff) };
    let Ok(current) = libc::c_ulong::try_from(current) else {
        return;
    };
    // SAFETY: personality takes one scalar argument.
    unsafe { libc::personality(current | AUDIT_PERSONALITY_MARKER) };
}
```

In the `pre_exec` closure, immediately after `set_no_new_privs()?;`, add:

```rust
                // (1b) Mark this process tree so host syscall auditing can
                //      attribute its denials. Best-effort; never fails.
                mark_for_audit();
```

**Verify**: `cargo build -p guardrail-linux` → exit 0, no new warnings.

### Step 3: Add a probe command

In `crates/guardrail-linux/src/bin/guardrail-probe.rs`:

1. Add to the `//!` command list at the top, after the `bpf` entry:

   ```
   //!   personality-marker
   //!                     exit 0 if this process carries guardrail's audit
   //!                     personality marker (0x3000000), 3 if it does not
   ```

2. Add a match arm before the final `_ =>` arm:

   ```rust
        "personality-marker" => {
            // SAFETY: personality with 0xffffffff only queries the value.
            let persona = unsafe { libc::personality(0xffff_ffff) };
            if persona >= 0 && (persona & 0x0300_0000) == 0x0300_0000 {
                exit(0)
            } else {
                exit(3)
            }
        }
   ```

3. Add `personality-marker` to the usage string in the `_ =>` arm.

**Verify**: `cargo build -p guardrail-linux --bins` → exit 0.

### Step 4: Add the integration test

Create `crates/guardrail-linux/tests/audit_marker.rs`:

```rust
//! The sandboxed process tree carries guardrail's audit personality marker.

#![cfg(target_os = "linux")]

use guardrail_core::Backend;
use guardrail_linux::LinuxBackend;

mod common;

const MARKER: libc::c_int = 0x0300_0000;

#[test]
fn sandboxed_child_carries_the_audit_marker() {
    // The probe checks after its own execve, so this also proves the marker
    // survives exec.
    let mut child = LinuxBackend::new(common::base())
        .expect("backend")
        .spawn(common::probe(&["personality-marker"]))
        .expect("spawn");
    assert_eq!(
        child.wait().expect("wait").code(),
        Some(0),
        "the sandboxed child must carry the audit personality marker"
    );
}

#[test]
fn spawning_does_not_mark_the_host_process() {
    let mut child = LinuxBackend::new(common::base())
        .expect("backend")
        .spawn(common::probe(&["personality-marker"]))
        .expect("spawn");
    child.wait().expect("wait");

    // SAFETY: personality with 0xffffffff only queries the value.
    let persona = unsafe { libc::personality(0xffff_ffff) };
    assert_eq!(
        persona & MARKER,
        0,
        "the marker is set after fork and must not leak into the host process"
    );
}
```

**Verify**: `cargo test -p guardrail-linux --test audit_marker` → 2 passed.

### Step 5: Confirm with a live audit daemon (needs root and `auditd`)

This step validates the documentation example. If the host has no root access
or no `auditctl`/`ausearch`, skip to step 6 and follow its "unverified"
instruction.

```
sudo auditctl -a always,exit -F arch=b64 -S all -F 'pers&=0x3000000' -F exit=-EROFS -k guardrail
sudo auditctl -a always,exit -F arch=b64 -S all -F 'pers&=0x3000000' -F exit=-EACCES -k guardrail
cargo test -p guardrail-linux --test filesystem
sudo ausearch -k guardrail --start recent | grep -c 'per=3000000'
sudo auditctl -D -k guardrail
```

**Verify**: the `grep -c` count is at least 1. Save one complete event
(the `SYSCALL` line and its `PATH` line) for the README. If `auditctl`
rejects the `pers&=` syntax, try `-F 'pers&0x3000000'` and record which form
worked; if neither loads, STOP.

### Step 6: Document

1. `crates/guardrail-linux/src/lib.rs`: add a crate-doc section immediately
   before `//! # Kernel attack surface and threat model`:

   ```rust
   //! # Audit marker
   //!
   //! Guardrail does not read or expose denial logs. Every sandboxed process
   //! tree is marked with `personality(2)` value `0x3000000` (`SHORT_INODE |
   //! WHOLE_SECONDS`, flags the kernel never reads). The value is inherited
   //! across `fork` and `execve`, appears as `per=3000000` in syscall audit
   //! records, and is matchable with an audit rule (`-F pers`). Nothing is
   //! logged unless the host administrator installs such rules. With them,
   //! every denial that reaches the kernel proper is recorded with the path
   //! the process used — including the mount-mask denials (`EROFS`,
   //! `EACCES`) that Landlock's own audit records cannot show. Syscalls
   //! refused by the seccomp filters never reach the audit entry hook and
   //! are not covered. The marker is best-effort: a host seccomp filter may
   //! refuse `personality(2)`, and a sandboxed process can clear it.
   //!
   ```

2. `crates/guardrail-napi/README.md`: if a `## Auditing Denials` section does
   not exist yet, create it immediately before `## Platform Capability Matrix`
   with this opening paragraph:

   > Guardrail does not collect or expose denial logs. It leaves markers in
   > each platform's own log so you can filter and attribute denials with the
   > tools you already run.

   Then add a `### Linux` subsection covering: what the marker is and that it
   is always on and silent; the two `auditctl` rules from step 5 plus the
   same rule with `-F exit=-EPERM`; that records show `per=3000000`, the
   process (`pid`, `comm`, `exe`) and a `PATH` record with the path as the
   process typed it; and the three limits (seccomp-refused syscalls are not
   covered; a lookup inside a read-denied directory that has a re-allowed
   descendant returns `ENOENT` and is not caught by these rules; the marker
   is best-effort and clearable).

   If step 5 ran: add a `Tested result:` line with the kernel version, the
   `auditctl` syntax that worked, and the saved event. If step 5 was skipped:
   write "Not yet verified against a live audit daemon." instead of a
   `Tested result:` line, and say so in your report.

**Verify**: `cargo test --doc` → pass;
`grep -c 'per=3000000' crates/guardrail-napi/README.md` ≥ 1.

## Test plan

- New: `crates/guardrail-linux/tests/audit_marker.rs` with the two tests in
  step 4, modeled on `tests/kernel_surface.rs`.
- All existing Linux tests must pass unchanged.
- Verification: `cargo test -p guardrail-linux --all-targets` → baseline + 2.

## Done criteria

- [ ] `cargo test -p guardrail-linux --all-targets` exits 0 with baseline + 2 tests
- [ ] `cargo test --all-targets` and `cargo test --doc` exit 0
- [ ] `grep -c 'mark_for_audit' crates/guardrail-linux/src/backend.rs` = 2
- [ ] `git diff --stat` shows no change under `crates/guardrail-core`
- [ ] README has `## Auditing Denials` → `### Linux`, with either a `Tested result:` line or the explicit "not yet verified" sentence
- [ ] No files outside the in-scope list are modified (`git status`)
- [ ] `plans/README.md` status row updated (write "DONE (audit example unverified)" if step 5 was skipped)

## STOP conditions

Stop and report back (do not improvise) if:

- The baseline fails with `Unsupported(…namespace…)` — wrong host.
- The code at the locations in "Current state" doesn't match the excerpts.
- `sandboxed_child_carries_the_audit_marker` fails. First check whether the
  host itself refuses `personality(2)` (run
  `python3 -c "import ctypes; print(ctypes.CDLL(None).personality(0x3000000))"`
  — `-1` means an ambient seccomp filter blocks it). If so, report that and
  re-run on a host without that filter; do not make the marker mandatory.
- Any existing test starts failing after step 2. The marker must be inert;
  a behavior change means an assumption in this plan is wrong.
- Neither `auditctl` syntax in step 5 loads.
- You find yourself wanting to add a config field or code that reads logs.

## Maintenance notes

- The marker is deliberately not a security boundary. If a future requirement
  is tamper-resistance, the answer is a seccomp rule on `personality(2)`, and
  it must be weighed against breaking `setarch`-style tools.
- If the kernel ever gives `SHORT_INODE` or `WHOLE_SECONDS` a meaning
  (unlikely: they are legacy SCO/Xenix emulation bits), the marker value must
  change, and the README must say so prominently because operators' audit
  rules embed it.
- Reviewer: confirm `mark_for_audit` cannot fail the spawn and performs no
  allocation, locking, or formatting.
- Deferred: emitting the rule index on Linux. Kernel records cannot carry
  free text; attribution is by joining the logged path against the policy.
