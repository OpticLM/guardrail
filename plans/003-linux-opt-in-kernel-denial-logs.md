# Plan 003: Opted-in Linux sandboxes have Landlock and seccomp record their own denials

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md` — unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**: `git diff --stat a5c8219..HEAD -- crates/guardrail-core crates/guardrail-linux crates/guardrail-napi crates/guardrail-macos crates/guardrail-windows`
> Plan 002 is expected to have changed: `crates/guardrail-core/src/config.rs`;
> in `crates/guardrail-linux`, `src/backend.rs`, `src/seccomp.rs`,
> `src/bin/guardrail-probe.rs`, `src/lib.rs`, `tests/common/mod.rs`, and the
> new `src/audit.rs` and `tests/audit_marker.rs`; in
> `crates/guardrail-napi`, `src/lib.rs`, the generated `binding.*` files, and
> the README; and one added line per `SandboxConfig` literal in the macOS and
> Windows crates. For any other difference, compare the "Current state"
> excerpts against the live code before proceeding; on a mismatch, treat it
> as a STOP condition.

## Status

- **Priority**: P2
- **Effort**: S
- **Risk**: MED
- **Depends on**: plans/002-linux-audit-marker.md (a code dependency: 002 adds the `linux_audit_denials` field this plan reads; both plans also edit `seccomp.rs`, the `pre_exec` closure, and the README's `## Auditing Denials` section)
- **Category**: direction
- **Planned at**: commit `a5c8219`, 2026-11-14; revised 2026-11-15

## Why this matters

Guardrail sandboxes LLM agents, and operators need to see when an agent hit a
sandbox rule. The design decision is that guardrail does **not** collect or
expose logs; it asks the operating system to write them, and operators
retrieve them with their own tools.

Plan 002 added the opt-in switch, `SandboxConfig::linux_audit_denials`, and
under it a pinned process marker so that the host's syscall audit rules can
record denials. Two things remain invisible after it:

1. **Syscalls refused by seccomp** — a `socket()` for a denied address family
   (the whole of `NetworkPolicy::Deny`), and the kernel-surface syscalls. The
   kernel runs seccomp *before* its audit entry hook, so these never produce a
   syscall audit record. Only seccomp's own logging can show them.
2. **Which access right Landlock refused.** A syscall record shows the path
   and the errno; Landlock's own record adds `blockers=fs.write_file` and
   similar, plus bind/connect ports and signal targets.

Both mechanisms can log natively, each with one flag. They are off today:
guardrail passes flags `0` to `landlock_restrict_self`, and the kernel does
not log Landlock denials after `execve` unless asked; seccomp logs `ERRNO`
and `TRAP` actions only when the filter was installed with
`SECCOMP_FILTER_FLAG_LOG`.

These flags make the kernel emit records on its own whenever host auditing is
enabled, and every probe a tool makes becomes a record. The kernel
documentation warns about exactly this for the Landlock flag. That is one
reason the maintainer made auditing **opt-in, via one config field, default
off**. This plan puts the two flags under the field plan 002 introduced. It
adds no second switch.

Facts verified while writing this plan:

- `include/uapi/linux/landlock.h`: `LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON`
  is `1U << 1`, available from Landlock ABI v7. Older kernels reject unknown
  flags with `EINVAL`, so the flag must only be passed on ABI ≥ 7.
- `kernel/seccomp.c` `seccomp_log()`: `SECCOMP_RET_TRAP` and
  `SECCOMP_RET_ERRNO` are logged only when the filter requested logging.
- seccompiler 0.5.0 (the version in `Cargo.lock`): `apply_filter` calls a
  private `apply_filter_with_flags(bpf_filter, 0)`; there is no public way to
  pass `SECCOMP_FILTER_FLAG_LOG`. The raw `seccomp(2)` call must be made by
  guardrail. `seccompiler::sock_filter` is public and `#[repr(C)]` with fields
  `code: u16, jt: u8, jf: u8, k: u32` — the same layout as
  `libc::sock_filter`.
- libc 0.2.186: `SECCOMP_FILTER_FLAG_LOG: c_ulong = 1 << 1`,
  `SECCOMP_SET_MODE_FILTER: c_uint = 1`, `struct sock_fprog { len: c_ushort,
  filter: *mut sock_filter }`.
- Kernel v6.18, checked 2026-11-15. When stacked seccomp filters return the
  same action, the newest filter wins the tie and its log flag alone decides
  (`seccomp_run_filters` compares with a strict `<`; `__seccomp_filter` calls
  `seccomp_log(…, match ? match->log : false)`). Landlock likewise takes the
  logging decision from the youngest layer that denies
  (`landlock_log_denial` in `security/landlock/audit.c`), and an outer
  domain has no flag to force logging. So a sandboxed process that stacks
  its own filter or domain can keep a denial out of the log, but only for an
  access its own layer also denies. Document this limit; do not try to
  prevent it.
- The probed-kernel (`EPERM`) filter carries plan 002's `personality(2)` pin.
  Once that filter is logged, an attempt to clear the audit marker appears as
  a `type=SECCOMP` record with `code=0x50001` and the `personality` syscall
  number (`135` on x86-64, `92` on aarch64).

## Current state

Line numbers below are as of `a5c8219`. Plan 002 adds lines to these files
and shifts them; the quoted code itself is unchanged by plan 002 unless
noted.

- `crates/guardrail-core/src/config.rs` — `SandboxConfig`, the plain-data
  policy. Plan 002 added the `linux_audit_denials: bool` field after
  `linux_user_namespaces`, with a doc comment that this plan extends.
- `crates/guardrail-linux/src/fs.rs` — `PreparedRuleset::restrict_self`, the
  single raw `landlock_restrict_self(2)` wrapper used for all three Landlock
  layers (filesystem, network, IPC).
- `crates/guardrail-linux/src/ipc.rs` — `pub(crate) fn query_abi() -> Result<i32>`
  returns the running kernel's Landlock ABI version.
- `crates/guardrail-linux/src/seccomp.rs` — builds up to four BPF programs and
  installs them. Since plan 002, the probed-kernel (`EPERM`) program also
  refuses marker-clearing `personality(2)` calls when the option is on.
- `crates/guardrail-linux/src/backend.rs` — the `pre_exec` closure.
- `crates/guardrail-napi/src/lib.rs` — Node option structs. Plan 002 added
  `linux_audit_denials: Option<bool>` to `SandboxOptions` and `SpawnOptions`
  with a doc comment that this plan extends.

`crates/guardrail-linux/src/fs.rs:282-296`:

```rust
    pub(crate) fn restrict_self(&self) -> std::io::Result<()> {
        // SAFETY: scalar args only; the fd is owned by self and stays open for
        // the duration of the call.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_landlock_restrict_self,
                self.fd.as_raw_fd(),
                0 as libc::c_uint,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
```

`crates/guardrail-linux/src/backend.rs` calls it three times inside the
closure: `landlock_ruleset.restrict_self()?;`,
`net_ruleset.restrict_self()?;`, `ipc_ruleset.restrict_self()?;`. The struct
and constructor (`backend.rs:8-43`; plan 002 adds a field and a probe call):

```rust
pub struct LinuxBackend {
    config: SandboxConfig,
    fs_rules: fs::CompiledRules,
    ipc_policy: ipc::Policy,
    net_ruleset: Option<fs::PreparedRuleset>,
    seccomp_programs: Vec<seccompiler::BpfProgram>,
}
```

```rust
    pub fn new(config: SandboxConfig) -> Result<Self> {
        Self::probe_support()?;
        let fs_rules = fs::compile(&config.fs)?;
        ns::probe_namespace_support()?;
        let ipc_policy = ipc::Policy::new(&config)?;
        let net_ruleset = net::prepare(&config)?;
        let seccomp_programs = seccomp::build(&config)?;
```

`crates/guardrail-linux/src/seccomp.rs:139-163` (program order matters):

```rust
pub(crate) fn build(config: &SandboxConfig) -> Result<Vec<BpfProgram>> {
    let mut programs = Vec::new();

    programs.push(compile(violation_rules(config), VIOLATION_ACTION)?);

    let network = network_rules(config.network)?;
    if !network.is_empty() {
        programs.push(compile(
            network,
            SeccompAction::Errno(libc::EAFNOSUPPORT as u32),
        )?);
    }

    programs.push(compile(
        probed_kernel_rules(config)?,
        SeccompAction::Errno(libc::EPERM as u32),
    )?);

    let enosys = enosys_rules(config);
    if !enosys.is_empty() {
        programs.push(compile(enosys, SeccompAction::Errno(libc::ENOSYS as u32))?);
    }

    Ok(programs)
}
```

The fourth (`ENOSYS`) program denies `clone3` and `io_uring_*` so that
runtimes fall back to older syscalls. glibc tries `clone3` on every thread
and process creation, so logging that program would flood the audit log. It
must never be logged.

`crates/guardrail-linux/src/seccomp.rs:255-268`:

```rust
pub(crate) fn apply(programs: &[BpfProgram]) -> std::io::Result<()> {
    for program in programs {
        seccompiler::apply_filter(program).map_err(|err| match err {
            // Errno-carrying variants pass their existing io::Error through
            // unchanged; it already holds a raw OS code and owns no heap.
            seccompiler::Error::Prctl(e) | seccompiler::Error::Seccomp(e) => e,
            // The remaining variants (empty filter, TSYNC) cannot occur for
            // the programs `build` produces and the flags `apply_filter`
            // passes; map them to a plain errno without formatting anything.
            _ => std::io::Error::from_raw_os_error(libc::EINVAL),
        })?;
    }
    Ok(())
}
```

Repo conventions that apply:

- KISS: the one boolean plan 002 added. No second field, no enum, no log
  reader, no new public function.
- Code in the `pre_exec` closure may only make raw syscalls: no allocation,
  locks, or formatting.
- Workspace clippy lints warn on `cast_sign_loss`,
  `undocumented_unsafe_blocks`, `multiple_unsafe_ops_per_block`,
  `unwrap_used`, `panic`, `indexing_slicing`. One unsafe operation per
  `unsafe` block, each with a `// SAFETY:` comment.
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
| Node binding | `cd crates/guardrail-napi && pnpm install --frozen-lockfile && pnpm build:debug && pnpm test` | all pass |

**Host requirement.** The Linux backend needs unprivileged user + mount + IPC
namespaces and an existing `/dev/mqueue` directory. On the cloud container
where this plan was written, `/dev/mqueue` is missing and the baseline fails
with `Unsupported(…namespace…)`; after `mkdir /dev/mqueue` (as root) the
suite passes there except
`network::outbound_only_keeps_ipv4_and_ipv6_connections`, which needs an
IPv6 loopback the container lacks. CI uses `ubuntu-latest` after
`sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`. Tests that
call `common::landlock_enforced()` skip silently unless securityfs is mounted
(`mount -t securityfs securityfs /sys/kernel/security`), and as root
`filesystem::read_allow_then_read_deny_denies_child_but_allows_sibling` fails
on unmodified code. Unlike plan 002's, this plan's code blocks have not been
built or run.

## Scope

**In scope**:
- `crates/guardrail-core/src/config.rs` (the field's doc comment only)
- `crates/guardrail-linux/src/fs.rs`, `src/seccomp.rs`, `src/backend.rs`,
  `src/lib.rs` (docs)
- `crates/guardrail-linux/tests/audit_denials.rs` (create)
- `crates/guardrail-napi/src/lib.rs` (the two fields' doc comments only),
  and the generated `crates/guardrail-napi/binding.d.ts`, `binding.cjs`,
  `binding.mjs` (only as regenerated by `pnpm build:debug`, never
  hand-edited)
- `crates/guardrail-napi/README.md`

**Out of scope** (do NOT touch):
- `seccompiler::apply_filter` remains the install path when the option is
  off. The default behavior must stay byte-for-byte what it is today.
- The `ENOSYS` seccomp program must never be logged.
- `VIOLATION_ACTION` stays `Trap`.
- Plan 002's marker, its `personality(2)` pin, and its construction-time
  check. This plan changes how filters are installed, not what they deny.
- A second config field. Marker and self-logging share one switch.
- Stopping a sandboxed process from stacking its own Landlock domain or
  seccomp filter (see the last verified fact above).
- Anything that reads audit logs or installs audit rules.
- The macOS and Windows crates. Plan 002 already added the field to their
  config literals.
- `crates/guardrail-linux/src/support.rs`: its `restrict_self()` calls are on
  the `landlock` crate's own type, not `PreparedRuleset`.

## Git workflow

- This repo uses jj colocated with git. If a `.jj` directory exists, use
  `jj describe -m "…"`; otherwise use git on a branch named
  `advisor/003-linux-opt-in-kernel-denial-logs`.
- One commit. Message:
  `core, linux, napi: log landlock and seccomp denials for audited sandboxes`.
- Do NOT push or open a PR unless the operator instructed it.

## Steps

### Step 1: Record the baseline

Run `cargo test -p guardrail-linux --all-targets` and
`cargo test --all-targets`.

**Verify**: both pass; note the counts. If the Linux suite fails with
`Unsupported(…namespace…)`, STOP. If
`grep -c 'linux_audit_denials' crates/guardrail-core/src/config.rs` is `0`,
STOP — plan 002 has not been applied.

### Step 2: Extend the config field's documentation

In `crates/guardrail-core/src/config.rs`, find the doc comment plan 002 wrote
on `pub linux_audit_denials: bool`. Insert this paragraph (with its blank
`///` separator lines) directly before the paragraph that begins
`/// Off by default`:

```rust
    /// It also asks Landlock and seccomp to record their own denials: the
    /// backend passes `LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON` for each
    /// Landlock layer on Landlock ABI v7 and newer (older kernels cannot log
    /// and are left unchanged), and installs its seccomp filters with
    /// `SECCOMP_FILTER_FLAG_LOG` — except the `ENOSYS` fallback filter, which
    /// every `clone3` attempt would otherwise flood. Whenever host auditing
    /// is on, the kernel then emits a record for every denied probe a tool
    /// makes.
    ///
```

Change no code in this file.

**Verify**: `cargo test -p guardrail-core --all-targets` → pass;
`grep -c 'SECCOMP_FILTER_FLAG_LOG' crates/guardrail-core/src/config.rs` = 1.

### Step 3: Landlock — pass the logging flag on ABI v7+

In `crates/guardrail-linux/src/fs.rs`:

1. Add near `PreparedRuleset`:

   ```rust
   /// `LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON`: log this domain's denials
   /// after `execve`. Landlock ABI v7+; older kernels reject it.
   const LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON: libc::c_uint = 1 << 1;

   /// Flags for `landlock_restrict_self(2)`: the logging flag only when the
   /// policy opted in and the kernel understands it.
   pub(crate) const fn restrict_self_flags(audit_denials: bool, abi: i32) -> libc::c_uint {
       if audit_denials && abi >= 7 {
           LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON
       } else {
           0
       }
   }
   ```

2. Change the signature to
   `pub(crate) fn restrict_self(&self, flags: libc::c_uint) -> std::io::Result<()>`
   and pass `flags` where `0 as libc::c_uint` is today.

In `crates/guardrail-linux/src/backend.rs`:

1. Add a field `landlock_flags: libc::c_uint` to `LinuxBackend`, computed in
   `new` before `config` is moved into the struct:

   ```rust
   let landlock_flags = fs::restrict_self_flags(config.linux_audit_denials, ipc::query_abi()?);
   ```

2. In `spawn`, next to `let limits = self.config.limits;`, add
   `let landlock_flags = self.landlock_flags;` and pass it to all three
   `restrict_self` calls in the closure.

**Verify**: `cargo build -p guardrail-linux` → exit 0, no new warnings;
`grep -c 'restrict_self(landlock_flags)' crates/guardrail-linux/src/backend.rs` = 3.

### Step 4: seccomp — log the three meaningful filters

In `crates/guardrail-linux/src/seccomp.rs`:

1. Add:

   ```rust
   /// A compiled filter and whether the kernel should record its denials.
   #[derive(Debug, Clone)]
   pub(crate) struct Filter {
       program: BpfProgram,
       log: bool,
   }

   // `install_logged` hands seccompiler's instructions to the kernel through
   // libc's `sock_fprog`; the two instruction types must have one layout.
   const _: () = assert!(
       size_of::<seccompiler::sock_filter>() == size_of::<libc::sock_filter>()
           && align_of::<seccompiler::sock_filter>() == align_of::<libc::sock_filter>()
   );
   ```

2. Change `build` to return `Result<Vec<Filter>>`. With
   `let log = config.linux_audit_denials;`, the violation (Trap), network
   (`EAFNOSUPPORT`), and probed-kernel (`EPERM`) programs become
   `Filter { program: compile(…)?, log }`. The `ENOSYS` program becomes
   `Filter { program: compile(…)?, log: false }` with a comment: "never
   logged: glibc attempts clone3 on every thread and process creation".

   The probed-kernel program is the one that holds plan 002's
   `personality(2)` pin. Logging it is what makes an attempt to clear the
   marker visible; leave the pin's rules as plan 002 wrote them.

3. Change `apply` to take `&[Filter]`. For a filter with `log == false`, keep
   the existing `seccompiler::apply_filter(&filter.program)` call and its
   error mapping exactly. For `log == true`, call a new function:

   ```rust
   /// Install `program` with `SECCOMP_FILTER_FLAG_LOG`, which seccompiler's
   /// `apply_filter` cannot pass. One raw `seccomp(2)`; NO_NEW_PRIVS was set
   /// earlier in `pre_exec`. Async-signal-safe.
   fn install_logged(program: &BpfProgram) -> std::io::Result<()> {
       let len = u16::try_from(program.len())
           .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
       if len == 0 {
           return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
       }
       let fprog = libc::sock_fprog {
           len,
           filter: program.as_ptr().cast::<libc::sock_filter>().cast_mut(),
       };
       // SAFETY: `fprog` points at `len` valid instructions that outlive the
       // call; the kernel copies the filter and does not write through it.
       let rc = unsafe {
           libc::syscall(
               libc::SYS_seccomp,
               libc::SECCOMP_SET_MODE_FILTER,
               libc::SECCOMP_FILTER_FLAG_LOG,
               std::ptr::from_ref(&fprog),
           )
       };
       if rc != 0 {
           return Err(std::io::Error::last_os_error());
       }
       Ok(())
   }
   ```

4. In `backend.rs`, change the field type to
   `seccomp_programs: Vec<seccomp::Filter>`. The rest of `spawn` compiles
   unchanged (`.clone()` and `seccomp::apply(&seccomp_programs)`).

5. Update the existing unit tests in `seccomp.rs` that inspect `build`'s
   result so they compile against `Vec<Filter>`. Plan 002's
   `personality_is_pinned_only_when_auditing` inspects `probed_kernel_rules`,
   not `build`, and needs no change.

**Verify**: `cargo test -p guardrail-linux --all-targets` → every baseline
test still passes, including plan 002's `tests/audit_marker.rs`.

### Step 5: Tests

1. In the `#[cfg(test)]` module of `fs.rs`, add
   `restrict_self_flags_follow_opt_in_and_abi`: `(false, 12) → 0`,
   `(true, 6) → 0`, `(true, 7) → 1 << 1`, `(true, 12) → 1 << 1`.

2. In the `#[cfg(test)]` module of `seccomp.rs`, add
   `only_the_enosys_filter_stays_unlogged_when_opted_in`: build with
   `linux_audit_denials: true` and default everything else (the module's
   existing tests use `..Default::default()`); assert the last filter has
   `log == false` and every other filter has `log == true`. Add
   `no_filter_is_logged_by_default`: with the default config every filter
   has `log == false`.

3. Create `crates/guardrail-linux/tests/audit_denials.rs`, modeled on
   `crates/guardrail-linux/tests/kernel_surface.rs` (copy its `status` and
   `trapped` helpers). With `let mut config = common::base();
   config.linux_audit_denials = true;` write four separate `#[test]`
   functions asserting that enforcement is unchanged:
   - `["socket-inet"]` exits with code `3`;
   - `["bpf"]` exits with code `3`;
   - `["mount"]` dies with `SIGSYS`;
   - `["echo-env", "X"]` exits with code `0` (the spawn itself works with
     the flags on whatever ABI this kernel has).

**Verify**: `cargo test -p guardrail-linux --all-targets` → baseline + 7.

### Step 6: Node binding documentation

The field already exists in the binding (plan 002). Its doc comment is
copied into the generated `binding.d.ts`, so update it and regenerate.

In `crates/guardrail-napi/src/lib.rs`, in both `SandboxOptions` and
`SpawnOptions`, add this line to the doc comment on
`pub linux_audit_denials: Option<bool>`, directly before the line that
begins `/// Guardrail never reads`:

```rust
    /// Also asks Landlock (ABI v7+) and seccomp to record their own denials.
```

Then regenerate and test:

```
cd crates/guardrail-napi && pnpm install --frozen-lockfile && pnpm build:debug && pnpm test
```

**Verify**: exit 0; `grep -c 'linuxAuditDenials' crates/guardrail-napi/binding.d.ts` = 2;
`grep -c 'record their own denials' crates/guardrail-napi/binding.d.ts` = 2.

### Step 7: Document

1. `crates/guardrail-linux/src/lib.rs`: extend the `//! # Auditing denials`
   section added by plan 002 with a paragraph on what the option adds here:
   what the two flags do, the ABI v7 floor for the Landlock half, that the
   `ENOSYS` filter is never logged, that each spawn creates up to three
   Landlock domains (filesystem, network, IPC), each with its own `domain=`
   id, and the stacking limit: a sandboxed process that adds its own
   Landlock domain or seccomp filter with logging off keeps a denial out of
   these records only when its own layer denies the same access.

2. `crates/guardrail-napi/README.md`:
   - In the table under `## Platform Capability Matrix`, extend the
     `linuxAuditDenials` row plan 002 added so its Linux cell also says
     "Landlock (ABI v7+) and seccomp record their own denials in the host
     audit log".
   - In `## Auditing Denials` → `### Linux` (written by plan 002), add a
     paragraph on the extra records an operator will see:
     `type=LANDLOCK_ACCESS … domain=<id> blockers=fs.write_file path="…"`;
     `type=LANDLOCK_DOMAIN … status=allocated … pid=<child.pid> exe="<host
     application>"` (the domain is created in the forked child before
     `execve`, so its `pid` equals the `pid` of the handle `spawn` returned);
     and `type=SECCOMP … syscall=<nr> code=0x50061` for a refused socket
     family (`0x50000` is "errno", `0x61` is `EAFNOSUPPORT`), `code=0x50001`
     for `EPERM`, `code=0x30000` for a trapped kernel-surface syscall. Say
     that a `SECCOMP` record with `code=0x50001` and the `personality`
     syscall number (`135` on x86-64, `92` on aarch64) is a process trying
     to clear the audit marker. State that the audit queue can drop records
     under load, so counts are a lower bound, and state the stacking limit
     from item 1 in one sentence.
   - In the same subsection, remove the limit plan 002 listed as "syscalls
     refused by seccomp are not covered", since this plan covers them.

**Verify**: `cargo test --doc` → pass;
`grep -c 'LANDLOCK_ACCESS' crates/guardrail-napi/README.md` ≥ 1.

## Test plan

- Unit: `restrict_self_flags` matrix (`fs.rs`); filter log marking
  (`seccomp.rs`).
- Integration: `tests/audit_denials.rs` — enforcement is unchanged with the
  option on.
- Not tested: that records actually reach the audit log. That needs root and
  a running audit daemon. If you have both, run
  `sudo ausearch -m LANDLOCK_ACCESS,SECCOMP --start recent` after the
  integration test and paste what it prints into your report; otherwise say
  so in the report. Do not add a test that requires root.
- Verification: `cargo test -p guardrail-linux --all-targets` → baseline + 7.

## Done criteria

- [ ] `cargo test --all-targets`, `cargo test --doc`, and `cargo test -p guardrail-linux --all-targets` exit 0
- [ ] `grep -c 'restrict_self(landlock_flags)' crates/guardrail-linux/src/backend.rs` = 3
- [ ] `grep -c 'seccompiler::apply_filter' crates/guardrail-linux/src/seccomp.rs` ≥ 1 (the default path is retained)
- [ ] `pnpm build:debug && pnpm test` exit 0 in `crates/guardrail-napi`
- [ ] `git diff --stat -- crates/guardrail-macos crates/guardrail-windows` shows nothing for this plan's commit
- [ ] No files outside the in-scope list are modified (`git status`)
- [ ] `plans/README.md` status row updated

## STOP conditions

Stop and report back (do not improvise) if:

- The baseline fails with `Unsupported(…namespace…)` — wrong host.
- `SandboxConfig` has no `linux_audit_denials` field — plan 002 has not been
  applied.
- The code at the locations in "Current state" doesn't match the excerpts
  (beyond the changes plan 002 makes).
- The compile-time layout assertion in step 4 fails. Do not weaken it.
- A spawn with `linux_audit_denials = true` fails with `EINVAL`. That means
  the Landlock flag reached a kernel below ABI v7 or the seccomp flag is
  unsupported; report the kernel version and `ipc::query_abi()` value.
- Any baseline test changes result with the option **off**.
- You find yourself wanting to add a second config field.
- `pnpm` or Node is unavailable (the tracked `binding.d.ts` must be
  regenerated, not hand-edited).

## Maintenance notes

- The seccomp program order in `build` and the "last filter is `ENOSYS`"
  assumption in the new unit test are coupled. If a filter is added, decide
  explicitly whether it is logged.
- If seccompiler later exposes a flags parameter, `install_logged` can be
  replaced by it and the layout assertion deleted.
- Landlock ABI v10 added `LANDLOCK_ADD_RULE_QUIET` (suppress logging for one
  object). If operators report noise from a known-benign probe path, that is
  the kernel-native answer; it was left out here to keep the surface at one
  boolean.
- The stacking limit is the kernel's design, not a guardrail bug: the newest
  denying layer owns the logging decision. If a future kernel lets an outer
  Landlock domain force logging of nested denials, pass that flag here.
- Reviewer: confirm the option-off path is unchanged, the raw syscall block
  has exactly one unsafe operation, and no macOS/Windows file changed.
