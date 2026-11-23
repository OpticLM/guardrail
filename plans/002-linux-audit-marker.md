# Plan 002: Opted-in Linux sandboxes carry a pinned marker the kernel audit trail can filter on

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md` — unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**: `git diff --stat a5c8219..HEAD -- crates/guardrail-core crates/guardrail-linux crates/guardrail-napi crates/guardrail-macos crates/guardrail-windows`
> If any in-scope file changed since this plan was written, compare the
> "Current state" excerpts against the live code before proceeding; on a
> mismatch, treat it as a STOP condition.

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: MED
- **Depends on**: none
- **Category**: direction
- **Planned at**: commit `a5c8219`, 2026-11-14; revised 2026-11-15

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
One `personality(2)` call provides it: the value (a) is inherited by every
descendant across `fork` and `execve`, (b) is printed as `per=` in every
syscall audit record, and (c) can be matched by an audit rule (`-F pers`).
Nothing is logged unless the host's administrator installs audit rules.

An earlier revision of this plan set that marker on every sandbox, best
effort. A design review on 2026-11-15 found two drawbacks, and the maintainer
decided to fix both:

1. **A sandboxed process could clear it.** `personality(2)` overwrites the
   whole word, and so does `setarch`: `setarch -R cmd` drops the marker by
   accident, and a process can drop it on purpose. This plan pins the marker
   with one seccomp rule, which makes it as irrevocable as the sandbox's
   other filters.
2. **A host could refuse it, silently.** systemd `LockPersonality=` and
   container seccomp profiles reject the call, and the sandbox then ran
   unmarked with no sign of it. This plan makes that an error: constructing
   the backend fails with `Error::Unsupported`, and a spawn fails rather than
   run unmarked.

Pinning has a cost — tools that rewrite the personality word fail inside the
sandbox — so the marker is no longer always on. It sits behind one opt-in
config field, `linux_audit_denials`, which plan 003 reuses for Landlock and
seccomp self-logging. With the field off, nothing is marked and nothing is
pinned.

Facts verified while writing this plan (do not re-derive, but do not
contradict). Kernel facts are from the v6.18 source unless noted.

- `personality(2)` flags `SHORT_INODE` (`0x1000000`) and `WHOLE_SECONDS`
  (`0x2000000`) are documented as "No effect" in the man page, and they are
  referenced nowhere except their definition in
  `include/uapi/linux/personality.h`. They are not in `PER_CLEAR_ON_SETID`.
- `kernel/exec_domain.c`: `personality(x)` stores `x` as the whole word
  unless `x` is `0xffffffff`, which only queries. `execve` keeps the two
  flags on x86-64 and arm64 (`set_personality_64bit`, `SET_PERSONALITY`, and
  `load_elf_binary` touch only `READ_IMPLIES_EXEC`). Other architectures
  were not checked.
- On kernel 6.18, a process that set `0x3000000` showed `03000000` in
  `/proc/self/personality` in its child and grandchild after `execve`, and
  `uname`, `date`, `ls`, and Python `select` behaved normally.
- `kernel/auditsc.c` prints ` per=%lx` in the SYSCALL record whenever the
  personality is not `PER_LINUX`, and `kernel/auditfilter.c` accepts every
  comparison operator (including bit tests) for the `pers` rule field.
- The audit rule fields that describe a process are its user and group ids,
  login session, security label, executable, pid, parent pid, and
  personality. There is none for namespaces, cgroups, seccomp state, or
  Landlock domains. Personality is the only one an unprivileged process can
  set, which is why the marker stays a personality value.
- util-linux `setarch` (master, 2026-11-15) calls `personality()` with its
  own value and does not OR in the current one.
- Hosts that refuse the marker: Docker's default seccomp profile allows
  `personality` only for the values `0x0`, `0x8`, `0x20000`, `0x20008`, and
  `0xffffffff`; systemd `LockPersonality=` "locks down the personality
  system call so that the kernel execution domain may not be changed".
- seccompiler 0.5.0: a rule map entry with several rules matches when any
  one rule matches; `SeccompCmpOp::MaskedEq` works with
  `SeccompCmpArgLen::Dword`; a compiled filter returns
  `SECCOMP_RET_KILL_PROCESS` for a syscall whose architecture is not the
  target's, so a 32-bit compat `personality` call cannot slip past the pin.
- The marker does **not** cover syscalls refused by seccomp (socket families,
  kernel-surface syscalls): the kernel runs seccomp before the audit entry
  hook, so those never produce a syscall audit record. Plan 003 covers them.
- **The code in this plan has been built and run.** On 2026-11-15 every code
  block below was applied to a copy of `a5c8219` on kernel 6.18.44 (x86-64).
  The nine new tests passed, the rest of the Linux suite was unchanged,
  `cargo clippy -p guardrail-linux --all-targets` reported nothing in the new
  code, `cargo fmt --all -- --check` was clean, and the Node binding built
  and passed `pnpm test`. The macOS and Windows edits were applied but could
  not be compiled there. Step 9 was run on the same host on 2026-11-16 with
  `auditctl` 3.1.2: the `pers&=0x3000000` syntax loaded and the denied write
  was recorded with `per=3000000`.

## Current state

- `crates/guardrail-core/src/config.rs` — `SandboxConfig`, the plain-data
  policy. Fields are public, and the construction sites listed in the table
  below write every field out, so a new field must be added at each.
- `crates/guardrail-linux/src/lib.rs` — crate docs and module list.
- `crates/guardrail-linux/src/backend.rs` — `LinuxBackend::new` and the
  `pre_exec` closure that applies confinement in the forked child.
- `crates/guardrail-linux/src/seccomp.rs` — builds the seccomp filters.
- `crates/guardrail-linux/src/bin/guardrail-probe.rs` — deterministic test
  helper; exits `0` (allowed), `3` (denied), `2` (usage or probe error).
- `crates/guardrail-linux/tests/` — integration tests that spawn the probe.
- `crates/guardrail-napi/src/lib.rs` — Node option structs and
  `build_config`.
- `crates/guardrail-napi/README.md` — user documentation.

`crates/guardrail-core/src/config.rs:97-102` (the field the new one follows):

```rust
    /// Linux-only user-namespace policy. Non-Linux backends ignore this field.
    ///
    /// Enforced with seccomp by the Linux backend. Denied by default; allow it
    /// only when the child runs its own nested sandbox (Chromium/Electron,
    /// bubblewrap, rootless containers). See [`UserNamespacePolicy`].
    pub linux_user_namespaces: UserNamespacePolicy,
```

The same file's doc example (`config.rs:44-57`) contains the line
`///     linux_user_namespaces: UserNamespacePolicy::Deny,`.

`crates/guardrail-linux/src/lib.rs:224-231`:

```rust
mod backend;
mod fs;
mod ipc;
mod net;
mod ns;
mod rlimit;
mod seccomp;
mod support;
```

`crates/guardrail-linux/src/backend.rs:5` and `:26-35`:

```rust
use crate::{fs, ipc, net, ns, rlimit, seccomp, support};
```

```rust
    /// or when the host forbids the unprivileged IPC/user/mount namespaces
    /// required for every sandbox's IPC isolation (see the crate-level
    /// namespace documentation).
    pub fn new(config: SandboxConfig) -> Result<Self> {
        Self::probe_support()?;
        let fs_rules = fs::compile(&config.fs)?;
        ns::probe_namespace_support()?;
        let ipc_policy = ipc::Policy::new(&config)?;
        let net_ruleset = net::prepare(&config)?;
        let seccomp_programs = seccomp::build(&config)?;
```

`crates/guardrail-linux/src/backend.rs:64` and `:82-94` (inside `spawn`):

```rust
        let limits = self.config.limits;
```

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

The closure runs after `fork` in a possibly multithreaded parent, so it may
only make raw syscalls: no allocation, no locks, no formatting. Seccomp is
applied last in the closure (`seccomp::apply(&seccomp_programs)?;`).

`ns::probe_namespace_support` (`crates/guardrail-linux/src/ns.rs:525-579`) is
the pattern for a construction-time check: it forks a disposable child, runs
the setup there, `_exit`s with a status, and the parent `waitpid`s and turns a
failure into `Error::Unsupported`. This plan adds a second, separate probe in
the same style and leaves `ns.rs` untouched.

`crates/guardrail-linux/src/seccomp.rs:46-49`, `:183-213`, and `:302-306`:

```rust
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule,
};
```

```rust
/// Rules mapped to `Errno(EPERM)`: kernel interfaces that legitimate tools
/// probe, plus namespace creation/joining under `UserNamespacePolicy::Deny`.
fn probed_kernel_rules(config: &SandboxConfig) -> Result<RuleMap> {
    let mut rules = RuleMap::new();
    for &sys in PROBED_KERNEL_SYSCALLS {
        add_whole_syscall_rule(&mut rules, sys);
    }
    if config.linux_user_namespaces == UserNamespacePolicy::Deny {
        let newuser = clone_newuser_rule()?;
        add_syscall_rule(&mut rules, libc::SYS_unshare, newuser.clone());
        add_syscall_rule(&mut rules, libc::SYS_clone, newuser);
        add_whole_syscall_rule(&mut rules, libc::SYS_setns);
    }
    Ok(rules)
}

/// A rule matching a `CLONE_NEWUSER`-bearing flags argument. `flags` is arg0
/// for both `unshare(2)` and, on the architectures seccompiler supports
/// (x86-64, aarch64, and riscv64), `clone(2)`. Dword: `CLONE_NEWUSER` sits in
/// the low 32 bits, and `unshare`'s C prototype takes a 32-bit int whose upper
/// register half is undefined.
fn clone_newuser_rule() -> Result<SeccompRule> {
    let condition = SeccompCondition::new(
        0, // arg0 = flags
        SeccompCmpArgLen::Dword,
        SeccompCmpOp::MaskedEq(libc::CLONE_NEWUSER as u64),
        libc::CLONE_NEWUSER as u64,
    )
    .map_err(|e| Error::confinement("seccomp", e))?;
    SeccompRule::new(vec![condition]).map_err(|e| Error::confinement("seccomp", e))
}
```

```rust
fn add_syscall_rule(rules: &mut RuleMap, syscall: i64, rule: SeccompRule) {
    for number in syscall_numbers(syscall) {
        rules.entry(number).or_default().push(rule.clone());
    }
}
```

`probed_kernel_rules` feeds the filter compiled with
`SeccompAction::Errno(libc::EPERM as u32)`; every filter's default action is
Allow, so a rule describes what to **deny**. `add_syscall_rule` also covers
the x32 syscall number on x86-64. The module doc at the top of `seccomp.rs`
describes each filter; its `EPERM` bullet ends at line 25 with
`//!   the same errno an unprivileged caller sees from a hardened kernel.`
The first unit test in the file's `mod tests` is
`enosys_rules_cover_every_io_uring_syscall_number` (line 365).

Probe binary, `crates/guardrail-linux/src/bin/guardrail-probe.rs`. The `//!`
command list ends at lines 119-120:

```rust
//!   bpf               call bpf(2); exit 0 if the syscall reaches the kernel,
//!                     3 if denied with EPERM
```

The `match` on the command name ends with the usage arm (`:1001-1018`), whose
string ends with the line
`unshare-user|mount|mount-setattr|kexec-load|bpf> [arg]"`. Arms call `exit`
with literal codes; `args` is the `Vec<String>` of process arguments.

Integration tests use `common::base()` (an exhaustive `SandboxConfig`
literal) and `common::probe(&[…])` from
`crates/guardrail-linux/tests/common/mod.rs`, and
`common::landlock_enforced()` to skip on kernels without Landlock.

`crates/guardrail-napi/src/lib.rs:338-341` (inside `build_config`'s
`SandboxConfig { … }` literal) and `:368` (inside
`impl From<SpawnOptions> for (SandboxOptions, SandboxSpawnOptions)`):

```rust
        linux_user_namespaces: opts
            .linux_user_namespaces
            .map(|u| u.into())
            .unwrap_or(UserNamespacePolicy::Deny),
```

```rust
                linux_user_namespaces: options.linux_user_namespaces,
```

Both option structs (`SandboxOptions` and `SpawnOptions`) declare
`pub linux_user_namespaces: Option<JsUserNamespacePolicy>,` (lines 137 and
194).

Files that contain exhaustive `SandboxConfig` literals or the Node option
plumbing. In every one of them the number of lines matching
`windows_acl_verification:` equals the number matching
`linux_user_namespaces:` (checked 2026-11-15), and each such pair sits in a
place that also needs the new field:

| File | Count |
|---|---|
| `crates/guardrail-core/src/config.rs` | 2 (doc example + field definition) |
| `crates/guardrail-linux/tests/common/mod.rs` | 2 |
| `crates/guardrail-macos/src/backend.rs` | 1 |
| `crates/guardrail-macos/src/profile.rs` | 15 |
| `crates/guardrail-macos/src/seatbelt.rs` | 3 |
| `crates/guardrail-macos/tests/common/mod.rs` | 2 |
| `crates/guardrail-napi/src/lib.rs` | 4 (two option structs, `build_config`, `From`) |
| `crates/guardrail-windows/tests/environment.rs` | 1 |
| `crates/guardrail-windows/tests/path_resolution.rs` | 1 |
| `crates/guardrail-windows/tests/policy.rs` | 1 |
| `crates/guardrail-windows/tests/process.rs` | 1 |
| `crates/guardrail-windows/tests/resource_limits.rs` | 1 |
| `crates/guardrail-windows/tests/stdio.rs` | 1 |

The macOS and Windows crates are native-only and will not be compiled on a
Linux host. Their edits are mechanical (one added line per literal) and are
checked here by a grep gate; CI compiles them on their own runners.

Library facts (libc 0.2.186, the version in `Cargo.lock`):
`pub fn personality(persona: c_ulong) -> c_int`; passing `0xffffffff` returns
the current value without changing it.

Repo conventions that apply:

- KISS: one boolean field. No enum, no log reader, no new public function.
- Platform-specific fields are prefixed with the platform
  (`linux_unix_sockets`, `linux_user_namespaces`, `darwin_sandbox_profiles`,
  `windows_cache_namespace`) and documented as ignored elsewhere.
- Workspace clippy lints (root `Cargo.toml`) warn on `cast_sign_loss`,
  `undocumented_unsafe_blocks`, `multiple_unsafe_ops_per_block`,
  `unwrap_used`, `panic`, `indexing_slicing`. Every `unsafe` block needs its
  own `// SAFETY:` comment and exactly one unsafe operation; convert integers
  with `try_from` / `from`, not `as`.
- In `crates/guardrail-napi`, use pnpm, not npm.
- Commit messages use scoped-commits form with comma-separated scopes when
  several areas are touched, e.g.
  `linux, napi: deny socket families with EAFNOSUPPORT instead of SIGSYS trap`.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Linux backend tests | `cargo test -p guardrail-linux --all-targets` | all pass |
| Default workspace tests | `cargo test --all-targets` | all pass |
| Doc tests | `cargo test --doc` | all pass |
| Lints | `cargo clippy -p guardrail-linux --all-targets` | no finding in files this plan touches |
| Formatting | `cargo fmt --all -- --check` | no output |
| Node binding | `cd crates/guardrail-napi && pnpm install --frozen-lockfile && pnpm build:debug && pnpm test` | all pass |

**Host requirement.** The Linux backend needs unprivileged user + mount + IPC
namespaces and an existing `/dev/mqueue` directory to mount a private message
queue filesystem on. On the cloud container where this plan was written,
`/dev/mqueue` is missing and the baseline fails with
`Unsupported("the Linux backend requires a fresh IPC namespace … creating
them failed: No such file or directory")`. After `mkdir /dev/mqueue` (as
root) the suite passes there except
`network::outbound_only_keeps_ipv4_and_ipv6_connections`, which needs an
IPv6 loopback the container lacks. CI uses `ubuntu-latest` after
`sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`.

Two more traps on that container. Tests that call `common::landlock_enforced()`
skip silently unless securityfs is mounted
(`mount -t securityfs securityfs /sys/kernel/security`). With it mounted and
the suite running as root,
`filesystem::read_allow_then_read_deny_denies_child_but_allows_sibling` fails
on unmodified code, because root keeps `CAP_DAC_OVERRIDE` inside the sandbox's
user namespace and can open a mode-0 mask (it reads as empty).

## Scope

**In scope** (the only files you should modify):
- `crates/guardrail-core/src/config.rs`
- `crates/guardrail-linux/src/audit.rs` (create)
- `crates/guardrail-linux/src/lib.rs` (one `mod` line, plus docs)
- `crates/guardrail-linux/src/backend.rs`
- `crates/guardrail-linux/src/seccomp.rs`
- `crates/guardrail-linux/src/bin/guardrail-probe.rs`
- `crates/guardrail-linux/tests/common/mod.rs`
- `crates/guardrail-linux/tests/audit_marker.rs` (create)
- `crates/guardrail-napi/src/lib.rs`, and the generated
  `crates/guardrail-napi/binding.d.ts`, `binding.cjs`, `binding.mjs` (only as
  regenerated by `pnpm build:debug`, never hand-edited)
- `crates/guardrail-napi/README.md`
- The macOS and Windows files in the table above — **only** the one added
  line per literal.

**Out of scope** (do NOT touch):
- Marking sandboxes that did not opt in. With the field off, the backend must
  make no `personality(2)` call and install no `personality` rule; the
  default behavior stays byte-for-byte what it is today.
- A best-effort marker. Once opted in, a host that refuses the marker is an
  error, never a silent skip.
- `crates/guardrail-linux/src/ns.rs`. The marker probe is a separate small
  function; do not fold it into `probe_namespace_support`.
- Landlock or seccomp logging flags — that is plan 003.
- Any code that reads audit logs, or that installs audit rules.
- Any macOS or Windows behavior. Those backends ignore the field.

## Git workflow

- This repo uses jj colocated with git. If a `.jj` directory exists, use
  `jj describe -m "…"`; otherwise use git on a branch named
  `advisor/002-linux-audit-marker`.
- One commit. Message:
  `core, linux, napi: opt-in pinned audit marker for linux sandboxes`.
- Do NOT push or open a PR unless the operator instructed it.

## Steps

### Step 1: Record the baseline

Run `cargo test -p guardrail-linux --all-targets` and
`cargo test --all-targets`.

**Verify**: both pass; note the counts. If the Linux suite fails with
`Unsupported(…namespace…)`, see "Host requirement"; if it still fails, STOP —
this host cannot run the backend.

### Step 2: Add the config field

In `crates/guardrail-core/src/config.rs`, add to `SandboxConfig` directly
after the `linux_user_namespaces` field:

```rust
    /// Linux-only opt-in: make this sandbox's denials attributable in the
    /// host audit log. Non-Linux backends ignore this field.
    ///
    /// When `true`, the Linux backend marks the sandboxed process tree with
    /// `personality(2)` value `0x3000000`, which syscall audit records print
    /// as `per=` and an audit rule can match (`-F pers`). A seccomp rule
    /// refuses every `personality(2)` call that would clear the marker, and
    /// constructing the backend fails with `Error::Unsupported` when the host
    /// refuses the marker, so an opted-in sandbox never runs unmarked.
    ///
    /// Off by default: the seccomp rule makes `setarch`-style tools fail with
    /// `EPERM` inside the sandbox. Guardrail never reads audit records and
    /// never installs audit rules; both are the host's job.
    pub linux_audit_denials: bool,
```

In the same file's doc example, add `///     linux_audit_denials: false,`
after the `linux_user_namespaces` line.

Then add the line `linux_audit_denials: false,` directly after every
`linux_user_namespaces:` line in the files listed in the "Current state"
table, except `crates/guardrail-core/src/config.rs` (done above) and
`crates/guardrail-napi/src/lib.rs` (handled in step 8). Keep each file's
indentation. Change nothing else in the macOS and Windows files.

**Verify**: `cargo test -p guardrail-core --all-targets` → pass, and this
loop prints nothing:

```
for f in $(grep -rl 'windows_acl_verification:' crates --include='*.rs' | grep -v guardrail-napi); do
  a=$(grep -c 'windows_acl_verification:' "$f"); b=$(grep -c 'linux_audit_denials:' "$f")
  [ "$a" = "$b" ] || echo "MISMATCH $f want=$a got=$b"
done
```

### Step 3: Add the marker module

Create `crates/guardrail-linux/src/audit.rs`:

```rust
//! The audit marker for opted-in sandboxes (`SandboxConfig::linux_audit_denials`).
//!
//! Guardrail does not read or expose denial logs. It marks the sandboxed
//! process tree so the host's own syscall auditing can select it: the marker
//! is inherited across `fork` and `execve`, printed as `per=` in every syscall
//! audit record, and matchable by an audit rule (`-F pers`). The seccomp
//! filters pin it (see `crate::seccomp`), so the tree cannot clear it.

use std::io;

use guardrail_core::{Error, Result};

/// `SHORT_INODE | WHOLE_SECONDS`: two `personality(2)` flags the kernel
/// defines but never reads.
pub(crate) const MARKER: u32 = 0x0300_0000;

/// Set [`MARKER`] on the calling process, keeping its other personality
/// bits. Fails when the host refuses `personality(2)`. Async-signal-safe.
pub(crate) fn mark() -> io::Result<()> {
    // SAFETY: personality takes one scalar argument; 0xffffffff only queries.
    let current = unsafe { libc::personality(0xffff_ffff) };
    let Ok(current) = libc::c_ulong::try_from(current) else {
        return Err(io::Error::last_os_error());
    };
    // SAFETY: personality takes one scalar argument.
    let previous = unsafe { libc::personality(current | libc::c_ulong::from(MARKER)) };
    if previous < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Verify that this host lets a process carry the marker. Runs [`mark`] in a
/// disposable forked child so the caller's own personality is untouched, and
/// so a host filter that kills on `personality(2)` only kills the child.
pub(crate) fn probe_marker_support() -> Result<()> {
    // SAFETY: fork takes no arguments; the child below only calls
    // async-signal-safe functions (personality, _exit) before exiting.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(Error::confinement(
            "audit marker probe",
            io::Error::last_os_error(),
        ));
    }
    if pid == 0 {
        let code = i32::from(mark().is_err());
        // SAFETY: immediate exit without running any Rust cleanup.
        unsafe { libc::_exit(code) };
    }

    let mut status: libc::c_int = 0;
    loop {
        // SAFETY: status is a valid out-pointer; pid is our direct child.
        let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
        if rc == pid {
            break;
        }
        let err = io::Error::last_os_error();
        if rc < 0 && err.raw_os_error() != Some(libc::EINTR) {
            return Err(Error::confinement("audit marker probe", err));
        }
    }

    if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
        return Ok(());
    }
    Err(Error::Unsupported(
        "linux_audit_denials marks sandboxed processes with personality(2), \
         which this host refuses (for example systemd LockPersonality= or a \
         container seccomp profile). Lift that restriction, or turn \
         linux_audit_denials off"
            .into(),
    ))
}
```

In `crates/guardrail-linux/src/lib.rs`, add `mod audit;` directly before
`mod backend;`.

**Verify**: `cargo build -p guardrail-linux` → exit 0. Warnings that `MARKER`,
`mark`, and `probe_marker_support` are unused are expected until step 4.

### Step 4: Wire the marker into the backend

In `crates/guardrail-linux/src/backend.rs`:

1. Change the import to
   `use crate::{audit, fs, ipc, net, ns, rlimit, seccomp, support};`.

2. In the doc comment of `LinuxBackend::new`, replace the last three lines
   (quoted under "Current state") with:

   ```rust
       /// when the host forbids the unprivileged IPC/user/mount namespaces
       /// required for every sandbox's IPC isolation (see the crate-level
       /// namespace documentation); or when `linux_audit_denials` is set and the
       /// host refuses the `personality(2)` audit marker (see the crate-level
       /// auditing documentation).
   ```

3. In `new`, directly after `ns::probe_namespace_support()?;`, add:

   ```rust
           if config.linux_audit_denials {
               audit::probe_marker_support()?;
           }
   ```

4. In `spawn`, directly after `let limits = self.config.limits;`, add
   `let audit_denials = self.config.linux_audit_denials;`.

5. In the `pre_exec` closure, directly after `set_no_new_privs()?;` and its
   following blank line, add:

   ```rust
                   // (1b) Audit marker, when the policy opted in: tag this
                   //      process tree so host syscall auditing can attribute
                   //      its denials. A refusal fails the spawn, so an opted-in
                   //      sandbox never runs unmarked. The seccomp filters
                   //      applied last pin the marker.
                   if audit_denials {
                       audit::mark()?;
                   }

   ```

**Verify**: `cargo build -p guardrail-linux` → exit 0, no warnings;
`grep -c 'audit::mark()' crates/guardrail-linux/src/backend.rs` = 1;
`grep -c 'audit::probe_marker_support()' crates/guardrail-linux/src/backend.rs` = 1.

### Step 5: Pin the marker with seccomp

In `crates/guardrail-linux/src/seccomp.rs`:

1. In the module doc, extend the `EPERM` bullet. Replace its last line,
   `//!   the same errno an unprivileged caller sees from a hardened kernel.`,
   with:

   ```rust
   //!   the same errno an unprivileged caller sees from a hardened kernel. When
   //!   the policy opts in to auditing, a `personality(2)` call that would clear
   //!   the audit marker joins this filter (see `crate::audit`).
   ```

2. After the `use seccompiler::{ … };` block, add a blank line and
   `use crate::audit;`.

3. Replace the doc comment of `probed_kernel_rules` with:

   ```rust
   /// Rules mapped to `Errno(EPERM)`: kernel interfaces that legitimate tools
   /// probe, plus namespace creation/joining under `UserNamespacePolicy::Deny`
   /// and, when the policy opts in to auditing, clearing the audit marker.
   ```

4. In `probed_kernel_rules`, directly before `Ok(rules)`, add:

   ```rust
       if config.linux_audit_denials {
           for rule in marker_clearing_rules()? {
               add_syscall_rule(&mut rules, libc::SYS_personality, rule);
           }
       }
   ```

5. Directly after `probed_kernel_rules`, add:

   ```rust
   /// Rules matching a `personality(2)` argument that would leave the audit
   /// marker incomplete: one rule per way its two bits can be. The query value
   /// `0xffffffff` has both bits set, so it matches none of them and stays
   /// allowed, as does any change that keeps the marker. Dword: the kernel reads
   /// the argument as a 32-bit `unsigned int`.
   fn marker_clearing_rules() -> Result<Vec<SeccompRule>> {
       const SHORT_INODE: u64 = 0x0100_0000;
       const WHOLE_SECONDS: u64 = 0x0200_0000;
       [0, SHORT_INODE, WHOLE_SECONDS]
           .into_iter()
           .map(|kept| {
               let condition = SeccompCondition::new(
                   0, // arg0 = persona
                   SeccompCmpArgLen::Dword,
                   SeccompCmpOp::MaskedEq(u64::from(audit::MARKER)),
                   kept,
               )
               .map_err(|e| Error::confinement("seccomp", e))?;
               SeccompRule::new(vec![condition]).map_err(|e| Error::confinement("seccomp", e))
           })
           .collect()
   }
   ```

   The filter's default action is Allow, so these rules name what to deny:
   a new value whose two marker bits are both clear, or only `SHORT_INODE`,
   or only `WHOLE_SECONDS`. Everything else — the query, and any value that
   keeps both bits — matches no rule and is allowed.

**Verify**: `cargo build -p guardrail-linux` → exit 0, no warnings.

### Step 6: Add probe commands

In `crates/guardrail-linux/src/bin/guardrail-probe.rs`:

1. Add to the `//!` command list at the top, after the `bpf` entry:

   ```rust
   //!   personality-marker
   //!                     exit 0 if this process carries guardrail's audit
   //!                     personality marker (0x3000000), 3 if it does not
   //!   personality-set <HEX>
   //!                     call personality(2) with the hexadecimal value HEX;
   //!                     exit 0 if allowed, 3 if denied with EPERM
   ```

2. Add two match arms before the final `_ =>` arm:

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
           "personality-set" => {
               let Some(persona) = args
                   .get(2)
                   .and_then(|arg| libc::c_ulong::from_str_radix(arg, 16).ok())
               else {
                   eprintln!("personality-set needs a hexadecimal personality value");
                   exit(2);
               };
               // SAFETY: personality takes one scalar argument.
               let previous = unsafe { libc::personality(persona) };
               if previous >= 0 {
                   exit(0);
               }
               match std::io::Error::last_os_error().raw_os_error() {
                   Some(libc::EPERM) => exit(3),
                   _ => exit(2),
               }
           }
   ```

3. In the usage string in the `_ =>` arm, replace the last line
   `unshare-user|mount|mount-setattr|kexec-load|bpf> [arg]"` with:

   ```rust
                    unshare-user|mount|mount-setattr|kexec-load|bpf|\
                    personality-marker|personality-set> [arg]"
   ```

**Verify**: `cargo build -p guardrail-linux --bins` → exit 0.

### Step 7: Add the tests

1. In the `#[cfg(test)] mod tests` of `crates/guardrail-linux/src/seccomp.rs`,
   add before `enosys_rules_cover_every_io_uring_syscall_number`:

   ```rust
       #[test]
       fn personality_is_pinned_only_when_auditing() {
           let audited = SandboxConfig {
               linux_audit_denials: true,
               ..SandboxConfig::default()
           };
           let rules = probed_kernel_rules(&audited).expect("rules");
           assert_eq!(rules.get(&libc::SYS_personality).map(Vec::len), Some(3));
           #[cfg(target_arch = "x86_64")]
           assert!(rules.contains_key(&(libc::SYS_personality | X32_SYSCALL_BIT)));

           let rules = probed_kernel_rules(&SandboxConfig::default()).expect("rules");
           assert!(!rules.contains_key(&libc::SYS_personality));
       }
   ```

2. Create `crates/guardrail-linux/tests/audit_marker.rs`:

   ```rust
   //! Opted-in sandboxes (`linux_audit_denials`) carry guardrail's audit
   //! personality marker, cannot clear it, and are refused on a host that will
   //! not let them carry it. Sandboxes that did not opt in are untouched.

   #![cfg(target_os = "linux")]

   use std::collections::BTreeMap;

   use guardrail_core::{Backend, Error, FsAccess, SandboxConfig};
   use guardrail_linux::LinuxBackend;
   use seccompiler::{BpfProgram, SeccompAction, SeccompFilter};
   use tempfile::TempDir;

   mod common;

   const MARKER: libc::c_int = 0x0300_0000;

   fn audited() -> SandboxConfig {
       let mut config = common::base();
       config.linux_audit_denials = true;
       config
   }

   /// Run the probe under `config` and return its exit code.
   fn exit_code(config: &SandboxConfig, args: &[&str]) -> Option<i32> {
       let mut child = LinuxBackend::new(config.clone())
           .expect("backend")
           .spawn(common::probe(args))
           .expect("spawn");
       child.wait().expect("wait").code()
   }

   #[test]
   fn audited_child_carries_the_marker() {
       // The probe checks after its own execve, so this also proves the marker
       // survives exec and that the pin leaves the personality query alone.
       assert_eq!(
           exit_code(&audited(), &["personality-marker"]),
           Some(0),
           "an opted-in sandbox must carry the audit personality marker"
       );
   }

   #[test]
   fn default_child_is_not_marked() {
       assert_eq!(
           exit_code(&common::base(), &["personality-marker"]),
           Some(3),
           "a sandbox that did not opt in must not be marked"
       );
   }

   #[test]
   fn audited_child_cannot_clear_the_marker() {
       // No marker bit, only SHORT_INODE, only WHOLE_SECONDS.
       for persona in ["0", "1000000", "2000000"] {
           assert_eq!(
               exit_code(&audited(), &["personality-set", persona]),
               Some(3),
               "personality({persona}) drops a marker bit and must fail with EPERM"
           );
       }
   }

   #[test]
   fn audited_child_may_change_other_personality_bits() {
       // 0x3040000 = marker | ADDR_NO_RANDOMIZE, what a debugger sets.
       assert_eq!(
           exit_code(&audited(), &["personality-set", "3040000"]),
           Some(0),
           "a personality change that keeps the marker must stay allowed"
       );
   }

   #[test]
   fn default_child_may_change_personality() {
       assert_eq!(
           exit_code(&common::base(), &["personality-set", "0"]),
           Some(0),
           "personality(2) must stay unrestricted when the option is off"
       );
   }

   #[test]
   fn spawning_does_not_mark_the_host_process() {
       exit_code(&audited(), &["personality-marker"]);

       // SAFETY: personality with 0xffffffff only queries the value.
       let persona = unsafe { libc::personality(0xffff_ffff) };
       assert_eq!(
           persona & MARKER,
           0,
           "the marker is set after fork and must not leak into the host process"
       );
   }

   #[test]
   fn audited_sandbox_still_denies_writes() {
       if !common::landlock_enforced() {
           eprintln!("skipping: Landlock not enforced on this kernel");
           return;
       }

       // A denied write from a marked process: the event a host audit rule
       // keyed on the marker records.
       let tmp = TempDir::new().expect("tempdir");
       let target = tmp.path().join("out.txt");
       let mut config = audited();
       config.fs.push(FsAccess::ReadAllow(tmp.path().into()));
       assert_eq!(
           exit_code(
               &config,
               &["write-file", target.to_str().expect("utf-8 path")]
           ),
           Some(3),
           "enforcement must be unchanged in an opted-in sandbox"
       );
   }

   #[test]
   fn construction_fails_when_the_host_refuses_personality() {
       // Stand in for a host that locks personality(2) (systemd
       // LockPersonality=): refuse it with EPERM on one disposable thread. The
       // probe child that `LinuxBackend::new` forks inherits the filter; the
       // other test threads never see it.
       std::thread::spawn(|| {
           let filter = SeccompFilter::new(
               BTreeMap::from([(libc::SYS_personality, vec![])]),
               SeccompAction::Allow,
               SeccompAction::Errno(libc::EPERM as u32),
               std::env::consts::ARCH.try_into().expect("arch"),
           )
           .expect("filter");
           let program: BpfProgram = filter.try_into().expect("program");
           seccompiler::apply_filter(&program).expect("install");

           assert!(
               matches!(LinuxBackend::new(audited()), Err(Error::Unsupported(_))),
               "an opted-in backend must refuse a host that refuses the marker"
           );
           assert!(
               LinuxBackend::new(common::base()).is_ok(),
               "a backend that did not opt in must not touch personality(2)"
           );
       })
       .join()
       .expect("probe thread");
   }
   ```

**Verify**: `cargo test -p guardrail-linux --test audit_marker` → 8 passed;
`cargo test -p guardrail-linux --all-targets` → baseline + 9;
`cargo clippy -p guardrail-linux --all-targets` reports nothing in
`audit.rs`, `audit_marker.rs`, `backend.rs`, `seccomp.rs`, or
`guardrail-probe.rs`; `cargo fmt --all -- --check` prints nothing.

### Step 8: Node binding

In `crates/guardrail-napi/src/lib.rs`:

1. In both `SandboxOptions` and `SpawnOptions`, after the
   `linux_user_namespaces` field, add:

   ```rust
       /// Linux-only opt-in: make this sandbox's denials attributable in the
       /// host audit log; `false` if omitted. Marks the sandboxed process tree
       /// with `personality(2)` value `0x3000000` for host syscall audit rules
       /// and pins it, so `setarch`-style tools fail with `EPERM` inside the
       /// sandbox. Building the sandbox fails when the host refuses the marker.
       /// Guardrail never reads audit records. Ignored on macOS and Windows.
       pub linux_audit_denials: Option<bool>,
   ```

2. In `build_config`'s literal, after the `linux_user_namespaces` entry
   (after its `.unwrap_or(UserNamespacePolicy::Deny),` line):
   `linux_audit_denials: opts.linux_audit_denials.unwrap_or(false),`

3. In the `From<SpawnOptions>` mapping, after `linux_user_namespaces`:
   `linux_audit_denials: options.linux_audit_denials,`

Then regenerate and test:

```
cd crates/guardrail-napi && pnpm install --frozen-lockfile && pnpm build:debug && pnpm test
```

**Verify**: exit 0; `grep -c 'linuxAuditDenials' crates/guardrail-napi/binding.d.ts` = 2;
`grep -c 'linux_audit_denials:' crates/guardrail-napi/src/lib.rs` = 4;
`cargo test --all-targets` → pass.

### Step 9: Confirm with a live audit daemon (needs root and `auditd`)

This step validates the documentation example. If the host has no root access
or no `auditctl`/`ausearch`, skip to step 10 and follow its "unverified"
instruction.

```
sudo auditctl -a always,exit -F arch=b64 -S all -F 'pers&=0x3000000' -F exit=-EROFS -k guardrail
sudo auditctl -a always,exit -F arch=b64 -S all -F 'pers&=0x3000000' -F exit=-EACCES -k guardrail
cargo test -p guardrail-linux --test audit_marker
sudo ausearch -k guardrail --start recent | grep -c 'per=3000000'
sudo auditctl -D -k guardrail
```

`audited_sandbox_still_denies_writes` makes a marked process fail a write
with `EACCES`, which the second rule records.

**Verify**: the `grep -c` count is at least 1. Save one complete event
(the `SYSCALL` line and its `PATH` line) for the README. If `auditctl`
rejects the `pers&=` syntax, try `-F 'pers&0x3000000'` and record which form
worked; if neither loads, STOP.

### Step 10: Document

1. `crates/guardrail-linux/src/lib.rs`: add a crate-doc section immediately
   before `//! # Kernel attack surface and threat model`:

   ```rust
   //! # Auditing denials
   //!
   //! Guardrail does not read or expose denial logs. With
   //! `SandboxConfig::linux_audit_denials`, it marks the sandboxed process tree
   //! with `personality(2)` value `0x3000000` (`SHORT_INODE | WHOLE_SECONDS`,
   //! flags the kernel never reads) so the host's own syscall auditing can
   //! select it. The value is inherited across `fork` and `execve`, appears as
   //! `per=3000000` in syscall audit records, and is matchable with an audit
   //! rule (`-F pers`). Nothing is logged unless the host administrator
   //! installs such rules. With them, every denial that reaches the kernel
   //! proper is recorded with the path the process used — including the
   //! mount-mask denials (`EROFS`, `EACCES`) that Landlock's own audit records
   //! cannot show. Syscalls refused by the seccomp filters never reach the
   //! audit entry hook and are not covered by the marker.
   //!
   //! The marker is part of the sandbox, not a hint. A seccomp rule refuses,
   //! with `EPERM`, every `personality(2)` call that would drop a marker bit,
   //! so the tree cannot clear it; queries and changes that keep both bits
   //! still work. Tools that overwrite the whole personality word (`setarch`,
   //! `linux32`) therefore fail inside an opted-in sandbox. A host that refuses
   //! `personality(2)` (systemd `LockPersonality=`, some container seccomp
   //! profiles) cannot carry the marker: constructing the backend fails with
   //! `Error::Unsupported`, and a spawn fails rather than run unmarked. With
   //! the option off, nothing is marked and `personality(2)` is unrestricted.
   //!
   ```

2. `crates/guardrail-napi/README.md`:
   - Add a row to the table under `## Platform Capability Matrix`, after the
     `linuxUserNamespaces` row: `linuxAuditDenials` | "opt-in: marks the
     sandboxed process tree with a pinned `personality(2)` value that host
     syscall audit rules can match; guardrail does not read the records" |
     ignored | ignored.
   - If a `## Auditing Denials` section does not exist yet, create it
     immediately before `## Platform Capability Matrix` with this opening
     paragraph:

     > Guardrail does not collect or expose denial logs. It leaves markers in
     > each platform's own log so you can filter and attribute denials with the
     > tools you already run.

   - Add a `### Linux` subsection covering: that the marker is set only with
     `linuxAuditDenials: true` and logs nothing by itself; the two `auditctl`
     rules from step 9 plus the same rule with `-F exit=-EPERM`; that records
     show `per=3000000`, the process (`pid`, `comm`, `exe`) and a `PATH`
     record with the path as the process typed it; that the marker is pinned,
     so `setarch`, `linux32`, and other tools that overwrite the personality
     word fail with `EPERM` inside the sandbox, while debuggers that add
     `ADDR_NO_RANDOMIZE` to the current value keep working; that building a
     sandbox fails on a host that refuses `personality(2)` (systemd
     `LockPersonality=`, Docker's default seccomp profile), and that an
     operator there can instead filter syscall audit records by the uid the
     agent runs as, which also matches the host application; and the two
     remaining limits (seccomp-refused syscalls are not covered; a lookup
     inside a read-denied directory that has a re-allowed descendant returns
     `ENOENT` and is not caught by these rules).

     If step 9 ran: add a `Tested result:` line with the kernel version, the
     `auditctl` syntax that worked, and the saved event. If step 9 was
     skipped: write "Not yet verified against a live audit daemon." instead
     of a `Tested result:` line, and say so in your report.

**Verify**: `cargo test --doc` → pass;
`grep -c 'per=3000000' crates/guardrail-napi/README.md` ≥ 1;
`grep -c 'linuxAuditDenials' crates/guardrail-napi/README.md` ≥ 2.

## Test plan

- Unit: `personality_is_pinned_only_when_auditing` in `seccomp.rs` — the pin
  exists exactly when the option is on, and covers the x32 number.
- Integration: `crates/guardrail-linux/tests/audit_marker.rs`, eight tests —
  the marker is present when opted in and absent otherwise; it cannot be
  cleared, fully or by one bit; a change that keeps it still works;
  `personality(2)` is unrestricted when the option is off; the host process
  is never marked; enforcement is unchanged; and construction fails on a
  host that refuses `personality(2)`.
- All existing Linux tests must pass unchanged.
- Not tested: that records reach the audit log (step 9, needs root).
- Verification: `cargo test -p guardrail-linux --all-targets` → baseline + 9.

## Done criteria

- [ ] `cargo test -p guardrail-linux --all-targets` exits 0 with baseline + 9 tests
- [ ] `cargo test --all-targets` and `cargo test --doc` exit 0
- [ ] The mismatch loop from step 2 prints nothing
- [ ] `grep -c 'audit::mark()' crates/guardrail-linux/src/backend.rs` = 1
- [ ] `git diff --stat -- crates/guardrail-linux/src/ns.rs` shows no change
- [ ] `pnpm build:debug && pnpm test` exit 0 in `crates/guardrail-napi`
- [ ] `git diff --stat -- crates/guardrail-macos crates/guardrail-windows` shows only added lines (no deletions)
- [ ] README has `## Auditing Denials` → `### Linux`, with either a `Tested result:` line or the explicit "not yet verified" sentence
- [ ] No files outside the in-scope list are modified (`git status`)
- [ ] `plans/README.md` status row updated (write "DONE (audit example unverified)" if step 9 was skipped)

## STOP conditions

Stop and report back (do not improvise) if:

- The baseline fails with `Unsupported(…namespace…)` and "Host requirement"
  does not fix it — wrong host.
- The code at the locations in "Current state" doesn't match the excerpts.
- `LinuxBackend::new` fails with the `linux_audit_denials … personality(2)`
  message in any test other than
  `construction_fails_when_the_host_refuses_personality`. The host itself
  refuses `personality(2)`: confirm with
  `python3 -c "import ctypes; print(ctypes.CDLL(None).personality(0x3000000))"`
  (`-1` means an ambient seccomp filter blocks it), report that, and re-run
  on a host without that filter. Do not make the marker best-effort.
- Any existing test changes result with the option **off**. The default path
  must be untouched; a behavior change means an assumption in this plan is
  wrong.
- A macOS or Windows file needs more than the one added line per literal.
- `pnpm` or Node is unavailable (the tracked `binding.d.ts` must be
  regenerated, not hand-edited).
- Neither `auditctl` syntax in step 9 loads.
- You find yourself wanting to mark sandboxes that did not opt in, weaken or
  drop the pin, add a second config field, or add code that reads logs.

## Maintenance notes

- Marker and pin are one unit. `audit::MARKER` and the two bit constants in
  `seccomp::marker_clearing_rules` must change together, and the marker must
  never be set without the pin: a clearable marker is the drawback this plan
  removes.
- If the kernel ever gives `SHORT_INODE` or `WHOLE_SECONDS` a meaning
  (unlikely: they are legacy SCO/Xenix emulation bits), the marker value must
  change, and the README must say so prominently because operators' audit
  rules embed it.
- `execve` keeping the two flags was checked for x86-64 and arm64 only. Before
  shipping a binary for another architecture, check its `SET_PERSONALITY`;
  `audited_child_carries_the_marker` fails if the flags are lost.
- Plan 003 logs the `EPERM` filter. From then on an attempt to clear the
  marker is itself recorded, as a `type=SECCOMP` record for the `personality`
  syscall.
- If Landlock gains a "do not inherit" rule flag (a
  `LANDLOCK_ADD_RULE_NO_INHERIT` series was under review upstream in 2026),
  deny-under-allow rules can become Landlock rules. Every filesystem denial
  is then logged natively with an unforgeable domain id, and this marker and
  its pin can be retired.
- Reviewer: confirm `audit::mark` performs no allocation, locking, or
  formatting; that the option-off path makes no `personality(2)` call and
  installs no `personality` rule; and that no macOS/Windows logic changed.
- Deferred: emitting the rule index on Linux. Kernel records cannot carry
  free text; attribution is by joining the logged path against the policy.
