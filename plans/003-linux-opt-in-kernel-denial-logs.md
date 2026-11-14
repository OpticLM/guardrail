# Plan 003: Linux hosts can opt in to Landlock and seccomp recording their own denials

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md` — unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**: `git diff --stat a5c8219..HEAD -- crates/guardrail-core crates/guardrail-linux crates/guardrail-napi crates/guardrail-macos crates/guardrail-windows`
> Plan 002 is expected to have changed `crates/guardrail-linux/src/backend.rs`,
> `src/bin/guardrail-probe.rs`, `src/lib.rs`, `tests/audit_marker.rs`, and the
> README. For any other difference, compare the "Current state" excerpts
> against the live code before proceeding; on a mismatch, treat it as a STOP
> condition.

## Status

- **Priority**: P2
- **Effort**: M
- **Risk**: MED
- **Depends on**: plans/002-linux-audit-marker.md (not a code dependency; both edit the `pre_exec` closure and the README's `## Auditing Denials` section, so apply 002 first)
- **Category**: direction
- **Planned at**: commit `a5c8219`, 2026-11-14

## Why this matters

Guardrail sandboxes LLM agents, and operators need to see when an agent hit a
sandbox rule. The design decision is that guardrail does **not** collect or
expose logs; it asks the operating system to write them, and operators
retrieve them with their own tools.

Plan 002 marks sandboxed processes so that the host's syscall audit rules can
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

Unlike plan 002's marker, these flags make the kernel emit records on its own
whenever host auditing is enabled, and every probe a tool makes becomes a
record. The kernel documentation warns about exactly this for the Landlock
flag. The maintainer therefore decided this must be **opt-in, via one config
field, default off**.

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

## Current state

- `crates/guardrail-core/src/config.rs` — `SandboxConfig`, the plain-data
  policy. Fields are public and every construction site in the repo writes
  **all** fields out (no `..Default::default()`), so a new field must be
  added at every site.
- `crates/guardrail-linux/src/fs.rs` — `PreparedRuleset::restrict_self`, the
  single raw `landlock_restrict_self(2)` wrapper used for all three Landlock
  layers (filesystem, network, IPC).
- `crates/guardrail-linux/src/ipc.rs` — `pub(crate) fn query_abi() -> Result<i32>`
  returns the running kernel's Landlock ABI version.
- `crates/guardrail-linux/src/seccomp.rs` — builds up to four BPF programs and
  installs them.
- `crates/guardrail-linux/src/backend.rs` — the `pre_exec` closure.
- `crates/guardrail-napi/src/lib.rs` — Node option structs and
  `build_config`.

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
and constructor (`backend.rs:8-43`):

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
plumbing, with the number of lines matching `windows_acl_verification:` in
each (use this as the checklist — every one of these lines sits in a place
that also needs the new field):

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

Repo conventions that apply:

- KISS: one boolean field. No enum, no log reader, no new public function.
- Platform-specific fields are prefixed with the platform
  (`linux_unix_sockets`, `linux_user_namespaces`, `darwin_sandbox_profiles`,
  `windows_cache_namespace`) and documented as ignored elsewhere.
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
namespaces. On the cloud container where this plan was written the baseline
fails with `Unsupported(…namespace…)`, so the suite was not confirmed green
there. Run on a host where the baseline passes (CI uses `ubuntu-latest`
after `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`).

## Scope

**In scope**:
- `crates/guardrail-core/src/config.rs`
- `crates/guardrail-linux/src/fs.rs`, `src/seccomp.rs`, `src/backend.rs`,
  `src/lib.rs` (docs)
- `crates/guardrail-linux/tests/common/mod.rs`,
  `crates/guardrail-linux/tests/audit_denials.rs` (create)
- `crates/guardrail-napi/src/lib.rs`, and the generated
  `crates/guardrail-napi/binding.d.ts`, `binding.cjs`, `binding.mjs` (only as
  regenerated by `pnpm build:debug`, never hand-edited)
- `crates/guardrail-napi/README.md`
- The macOS and Windows files in the table above — **only** the one added
  line per literal.

**Out of scope** (do NOT touch):
- `seccompiler::apply_filter` remains the install path when the option is
  off. The default behavior must stay byte-for-byte what it is today.
- The `ENOSYS` seccomp program must never be logged.
- `VIOLATION_ACTION` stays `Trap`.
- Anything that reads audit logs or installs audit rules.
- Any macOS or Windows behavior. Those backends ignore the field.
- `crates/guardrail-linux/src/support.rs`: its `restrict_self()` calls are on
  the `landlock` crate's own type, not `PreparedRuleset`.

## Git workflow

- This repo uses jj colocated with git. If a `.jj` directory exists, use
  `jj describe -m "…"`; otherwise use git on a branch named
  `advisor/003-linux-opt-in-kernel-denial-logs`.
- One commit. Message:
  `core, linux, napi: opt-in landlock and seccomp denial logging`.
- Do NOT push or open a PR unless the operator instructed it.

## Steps

### Step 1: Record the baseline

Run `cargo test -p guardrail-linux --all-targets` and
`cargo test --all-targets`.

**Verify**: both pass; note the counts. If the Linux suite fails with
`Unsupported(…namespace…)`, STOP.

### Step 2: Add the config field

In `crates/guardrail-core/src/config.rs`, add to `SandboxConfig` directly
after the `linux_user_namespaces` field:

```rust
    /// Linux-only opt-in: ask Landlock and seccomp to record their own
    /// denials in the host audit log. Non-Linux backends ignore this field.
    ///
    /// When `true`, the Linux backend passes
    /// `LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON` for each Landlock layer on
    /// Landlock ABI v7 and newer (older kernels cannot log and are left
    /// unchanged), and installs its seccomp filters with
    /// `SECCOMP_FILTER_FLAG_LOG` — except the `ENOSYS` fallback filter, which
    /// every `clone3` attempt would otherwise flood.
    ///
    /// Off by default: once enabled, the kernel emits a record for every
    /// denied probe a tool makes whenever host auditing is on. Guardrail
    /// never reads these records; retrieving them is the host's job.
    pub linux_audit_denials: bool,
```

In the same file's doc example, add `///     linux_audit_denials: false,`
after the `linux_user_namespaces` line.

Then add the line `linux_audit_denials: false,` after the
`linux_user_namespaces:` line in **every** `SandboxConfig { … }` literal in
the files listed in the "Current state" table, except
`crates/guardrail-napi/src/lib.rs` (handled in step 6). Keep each file's
indentation. Change nothing else in the macOS and Windows files.

**Verify**: `cargo test -p guardrail-core --all-targets` → pass, and this
loop prints nothing:

```
for f in $(grep -rl 'windows_acl_verification:' crates --include='*.rs' | grep -v guardrail-napi); do
  a=$(grep -c 'windows_acl_verification:' "$f"); b=$(grep -c 'linux_audit_denials:' "$f")
  [ "$a" = "$b" ] || echo "MISMATCH $f want=$a got=$b"
done
```

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
   result so they compile against `Vec<Filter>`.

**Verify**: `cargo test -p guardrail-linux --all-targets` → every baseline
test still passes.

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

### Step 6: Node binding

In `crates/guardrail-napi/src/lib.rs`:

1. In both `SandboxOptions` and `SpawnOptions`, after the
   `linux_user_namespaces` field, add:

   ```rust
       /// Linux-only opt-in: ask Landlock (ABI v7+) and seccomp to record
       /// their own denials in the host audit log. `false` if omitted.
       /// Guardrail never reads those records. Ignored on macOS and Windows.
       pub linux_audit_denials: Option<bool>,
   ```

2. In `build_config`'s literal, after the `linux_user_namespaces` entry:
   `linux_audit_denials: opts.linux_audit_denials.unwrap_or(false),`

3. In the `From<SpawnOptions>` mapping, after `linux_user_namespaces`:
   `linux_audit_denials: options.linux_audit_denials,`

Then regenerate and test:

```
cd crates/guardrail-napi && pnpm install --frozen-lockfile && pnpm build:debug && pnpm test
```

**Verify**: exit 0; `grep -c 'linuxAuditDenials' crates/guardrail-napi/binding.d.ts` = 2;
`grep -c 'linux_audit_denials:' crates/guardrail-napi/src/lib.rs` = 4.

### Step 7: Document

1. `crates/guardrail-linux/src/lib.rs`: extend the `//! # Audit marker`
   section added by plan 002 (or, if absent, add a section before
   `//! # Kernel attack surface and threat model`) with a paragraph on
   `SandboxConfig::linux_audit_denials`: what the two flags do, the ABI v7
   floor for the Landlock half, that the `ENOSYS` filter is never logged, and
   that each spawn creates up to three Landlock domains (filesystem, network,
   IPC), each with its own `domain=` id.

2. `crates/guardrail-napi/README.md`:
   - Add a row to the table under `## Platform Capability Matrix`:
     `linuxAuditDenials` | "opt-in: Landlock (ABI v7+) and seccomp record
     their own denials in the host audit log; guardrail does not read them" |
     ignored | ignored.
   - In `## Auditing Denials` → `### Linux` (create both if plan 002 has not
     run; the section goes immediately before `## Platform Capability
     Matrix`), add a paragraph on the opt-in records an operator will see:
     `type=LANDLOCK_ACCESS … domain=<id> blockers=fs.write_file path="…"`;
     `type=LANDLOCK_DOMAIN … status=allocated … pid=<child.pid> exe="<host
     application>"` (the domain is created in the forked child before
     `execve`, so its `pid` equals the `pid` of the handle `spawn` returned);
     and `type=SECCOMP … syscall=<nr> code=0x50061` for a refused socket
     family (`0x50000` is "errno", `0x61` is `EAFNOSUPPORT`), `code=0x50001`
     for `EPERM`, `code=0x30000` for a trapped kernel-surface syscall. State
     that the audit queue can drop records under load, so counts are a lower
     bound.

**Verify**: `cargo test --doc` → pass;
`grep -c 'linuxAuditDenials' crates/guardrail-napi/README.md` ≥ 2.

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
- [ ] The mismatch loop from step 2 prints nothing
- [ ] `grep -c 'restrict_self(landlock_flags)' crates/guardrail-linux/src/backend.rs` = 3
- [ ] `grep -c 'seccompiler::apply_filter' crates/guardrail-linux/src/seccomp.rs` ≥ 1 (the default path is retained)
- [ ] `pnpm build:debug && pnpm test` exit 0 in `crates/guardrail-napi`
- [ ] `git diff --stat -- crates/guardrail-macos crates/guardrail-windows` shows only added lines (no deletions)
- [ ] No files outside the in-scope list are modified (`git status`)
- [ ] `plans/README.md` status row updated

## STOP conditions

Stop and report back (do not improvise) if:

- The baseline fails with `Unsupported(…namespace…)` — wrong host.
- The code at the locations in "Current state" doesn't match the excerpts
  (beyond the changes plan 002 makes).
- The compile-time layout assertion in step 4 fails. Do not weaken it.
- A spawn with `linux_audit_denials = true` fails with `EINVAL`. That means
  the Landlock flag reached a kernel below ABI v7 or the seccomp flag is
  unsupported; report the kernel version and `ipc::query_abi()` value.
- Any baseline test changes result with the option **off**.
- A macOS or Windows file needs more than the one added line per literal.
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
- Reviewer: confirm the option-off path is unchanged, the raw syscall block
  has exactly one unsafe operation, and no macOS/Windows logic changed.
- This plan's macOS and Windows edits are only compile-checked by CI on
  those runners. Watch the first CI run.
