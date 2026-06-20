# Plan 003: Add Landlock filesystem confinement to `guardrail-linux`

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving on. If
> anything in "STOP conditions" occurs, stop and report — do not improvise.
> When done, update the status row for this plan in `plans/README.md`.
>
> **Drift check (run first)**: `git diff --stat <SHA-from-Status>..HEAD -- crates/guardrail-linux/src/lib.rs crates/guardrail-core/src/`
> This plan edits the `pre_exec` hook created by plan 002 and the probe binary.
> If `crates/guardrail-linux/src/lib.rs` no longer contains the documented
> "INSERTION POINT", reconcile before proceeding; on a real mismatch, STOP.

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: MED (kernel LSM; a wrong default-read set makes the target binary unrunnable)
- **Depends on**: plans/001, plans/002 (needs `LinuxBackend`, the `pre_exec`
  scaffold, and the `guardrail-probe` helper). Independent of plans 004/005.
- **Category**: security (filesystem confinement)
- **Planned at**: commit `a1d2a66`, 2026-06-21 (re-run drift check against the post-002 tree)

## Why this matters

Filesystem confinement is the core of the sandbox (`spec.md` §2, §5.1): untrusted
LLM code must not read secrets (`~/.ssh`, `~/.aws`, `.env` files) or write
outside what was granted. This plan uses the **Landlock LSM** (`spec.md` §4.1,
"compiles policies directly within Rust code into a Landlock ruleset") to enforce
the declarative `FsAccess::Read`/`FsAccess::Write` grants from `guardrail-core`.

The subtlety that makes or breaks this plan: Landlock denies **everything** not
explicitly allowed — *including the ability to load and execute the target
binary and its shared libraries*. So the default ruleset must grant read+execute
on standard system directories (`spec.md` §2: "Read-only access to base system
libraries by default"), or every `spawn` fails with ENOENT/EACCES before the
program even starts.

## Current state

After plan 002, `crates/guardrail-linux/src/lib.rs` contains a `LinuxBackend`
whose `Backend::spawn` installs a `pre_exec` closure. The closure currently does
`set_no_new_privs()` then `rlimit::apply(&limits)` and has this documented
insertion point (quote it to confirm you're at the right spot):

```rust
                // (3) INSERTION POINT — later plans add, in this order:
                //       fs::apply(&fs_rules)?;        // plan 003 (Landlock)
                //       seccomp::apply(&filter)?;     // plans 004/005 (last)
```

`guardrail_core` exposes (from plan 001), unchanged:
- `FsAccess::Read(PathBuf)` and `FsAccess::Write(PathBuf)`
- `SandboxConfig.fs: Vec<FsAccess>`
- `Error::confinement(stage: &'static str, source)` for wrapping backend errors.

The `guardrail-probe` binary (plan 002) currently handles `echo-env`, `alloc`,
`spin`. This plan adds `read-file <PATH>` and `write-file <PATH>` commands.

### Landlock API you will use (`landlock` crate v0.4.x — verified)

The builder flow and the result type (confirmed against docs.rs):

```rust
use landlock::{
    ABI, Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreatedAttr, RulesetStatus, path_beneath_rules,
};

let abi = ABI::V1; // pin a tested ABI; best-effort downgrades on older kernels
let status = Ruleset::default()
    .handle_access(AccessFs::from_all(abi))?   // we mediate ALL fs access rights
    .create()?                                  // -> RulesetCreated
    .add_rules(path_beneath_rules(read_paths, AccessFs::from_read(abi)))?
    .add_rules(path_beneath_rules(write_paths, AccessFs::from_all(abi)))?
    .restrict_self()?;                          // -> RestrictionStatus
// status.ruleset is RulesetStatus::{FullyEnforced|PartiallyEnforced|NotEnforced}
```

Key facts (do not deviate without checking docs-rs):
- `path_beneath_rules(paths, access)` **silently ignores paths that cannot be
  opened**. That is the desired best-effort behavior for the default system
  dirs (e.g. `/lib64` may not exist on a given distro).
- `AccessFs::from_read(abi)` = read+execute+readdir; `AccessFs::from_all(abi)` =
  read+write+create+remove+etc. Use `from_all` for `Write` grants and the
  ephemeral nothing-else case; use `from_read` for `Read` grants and system dirs.
- `restrict_self()` also sets `no_new_privs` (we already set it in plan 002;
  harmless to have it set again).
- The crate defaults to **best-effort** compatibility: on a kernel without
  Landlock, `restrict_self()` returns `Ok` with `RulesetStatus::NotEnforced`
  rather than erroring. Tests must account for this (see Test plan).
- `landlock::Ruleset` and the rule-building allocate; this runs inside
  `pre_exec`. That matches established sandbox crates (e.g. birdcage). Keep the
  code allocation-light but do not attempt to make it allocation-free.

## Commands you will need

| Purpose            | Command                                                          | Expected            |
|--------------------|------------------------------------------------------------------|---------------------|
| Build              | `cargo build -p guardrail-linux`                                 | exit 0              |
| Test (this plan)   | `cargo test -p guardrail-linux --test filesystem`                | all pass            |
| Full crate test    | `cargo test -p guardrail-linux`                                  | all pass            |
| Lint               | `cargo clippy -p guardrail-linux --all-targets -- -D warnings`   | exit 0              |
| Format check       | `cargo fmt --check`                                              | exit 0              |
| Kernel Landlock?   | `grep -i landlock /sys/kernel/security/lsm 2>/dev/null; uname -r`| host shows it ON    |

This host runs kernel `7.0.8` with Landlock available, so `FullyEnforced` is the
expected status locally.

## Suggested executor toolkit

- Use the **`docs-rs` MCP** on crate `landlock` for `Ruleset`, `AccessFs`,
  `path_beneath_rules`, `PathFd`, `RulesetStatus`, `RulesetError` before writing
  — the API uses a typestate builder and the method chain must be exact.

## Scope

**In scope** (create/modify only these):
- `Cargo.toml` (root) — add `landlock` to `[workspace.dependencies]`
- `crates/guardrail-linux/Cargo.toml` — depend on `landlock`
- `crates/guardrail-linux/src/fs.rs` (create — ruleset construction)
- `crates/guardrail-linux/src/lib.rs` — declare `mod fs;`, call `fs::apply` at
  the insertion point
- `crates/guardrail-linux/src/bin/guardrail-probe.rs` — add `read-file` /
  `write-file` commands
- `crates/guardrail-linux/tests/filesystem.rs` (create)
- `plans/README.md` (status update)

**Out of scope**:
- seccomp / network / IPC (plans 004/005). Do not touch `seccomp.rs` (it doesn't
  exist yet) and do not add `seccompiler`.
- `guardrail-core` — its `FsAccess` model is fixed. STOP if you think you need to
  change it.
- The ephemeral-workspace feature from `spec.md` §1.4 — explicitly dropped for
  this project. Do **not** create temp dirs, change the child's cwd, or add
  cleanup-on-Drop. Only the declared `Read`/`Write` grants plus the default
  system-dir reads.

## Version control

Repo uses **jj** colocated with git. **Do not commit/branch/push.** Leave changes
in the working copy.

## Steps

### Step 1: Add the `landlock` dependency

- Root `Cargo.toml` `[workspace.dependencies]`: add `landlock = "0.4"`.
- `crates/guardrail-linux/Cargo.toml` `[dependencies]`: add `landlock.workspace = true`.

**Verify**: `cargo fetch -p guardrail-linux` (or `cargo build -p guardrail-linux`)
resolves `landlock` 0.4.x → exit 0.

### Step 2: Implement `fs.rs` — build and apply the Landlock ruleset

Create `crates/guardrail-linux/src/fs.rs`. Requirements:

- A `pub(crate) fn apply(rules: &[FsAccess]) -> Result<(), guardrail_core::Error>`
  called from `pre_exec`.
- Always grant **read+execute** on a fixed set of system directories so the
  target binary and its libraries load. Use this set (paths that don't exist are
  ignored by `path_beneath_rules`):
  `["/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc"]`.
  Rationale: `/usr`,`/lib*`,`/bin`,`/sbin` cover binaries + shared objects +
  the dynamic loader; `/etc` covers `ld.so.cache`, `nsswitch.conf`, locale, etc.
  These are **read-only** — write is never granted by default.
- Map declared grants:
  - `FsAccess::Read(p)` → read access on `p`
  - `FsAccess::Write(p)` → full access (`from_all`) on `p`
- Pin `ABI::V1` (broadest kernel support; the read/exec/write rights this
  sandbox needs all exist in V1).
- On a kernel without Landlock, `restrict_self()` returns
  `RulesetStatus::NotEnforced`. **Do not error** in that case — return `Ok(())`
  (best-effort, per the crate's design and `spec.md`'s tolerance for partial
  enforcement). Optionally `eprintln!` a one-line warning. (Hard-failing would
  make the library unusable on older kernels; observability of the weak state is
  the caller's concern.)
- Wrap any `RulesetError` in `Error::confinement("landlock", err)`.

Target shape:

```rust
//! Filesystem confinement via the Landlock LSM.

use landlock::{
    ABI, Access, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus,
    path_beneath_rules,
};

use guardrail_core::{Error, FsAccess};

/// Read-only system directories always granted so the target binary, its
/// dynamic loader, and shared libraries can be loaded and executed.
const SYSTEM_READ_DIRS: &[&str] = &["/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc"];

/// Build and enforce a Landlock ruleset for `rules`. Called inside `pre_exec`.
pub(crate) fn apply(rules: &[FsAccess]) -> Result<(), Error> {
    let abi = ABI::V1;

    let read_paths: Vec<&str> = SYSTEM_READ_DIRS.to_vec();

    let mut ruleset = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .map_err(|e| Error::confinement("landlock", e))?
        .create()
        .map_err(|e| Error::confinement("landlock", e))?
        // Default read-only system directories.
        .add_rules(path_beneath_rules(read_paths, AccessFs::from_read(abi)))
        .map_err(|e| Error::confinement("landlock", e))?;

    // Declared read grants.
    for rule in rules {
        if let FsAccess::Read(p) = rule {
            ruleset = ruleset
                .add_rules(path_beneath_rules([p], AccessFs::from_read(abi)))
                .map_err(|e| Error::confinement("landlock", e))?;
        }
    }
    // Declared write grants (full access on the path).
    for rule in rules {
        if let FsAccess::Write(p) = rule {
            ruleset = ruleset
                .add_rules(path_beneath_rules([p], AccessFs::from_all(abi)))
                .map_err(|e| Error::confinement("landlock", e))?;
        }
    }

    let status = ruleset
        .restrict_self()
        .map_err(|e| Error::confinement("landlock", e))?;

    if status.ruleset == RulesetStatus::NotEnforced {
        eprintln!(
            "guardrail: warning — Landlock not enforced on this kernel; \
             filesystem confinement is INACTIVE"
        );
    }
    Ok(())
}
```

> If a method name in the chain doesn't resolve (the crate uses a typestate
> builder via the `RulesetAttr`/`RulesetCreatedAttr` traits — both must be in
> scope), check it on docs.rs rather than guessing. `path_beneath_rules`
> accepts any `IntoIterator<Item: AsRef<Path>>`; `[p]` and `read_paths` both work.

**Verify**: deferred to Step 4 (needs the `mod fs;` wiring).

### Step 3: Wire `fs::apply` into the `pre_exec` hook

In `crates/guardrail-linux/src/lib.rs`:
- Add `mod fs;` near `mod rlimit;`.
- Clone the FS rules out of `config` **before** the `unsafe` block (the closure
  is `'static`):
  ```rust
  let fs_rules = config.fs.clone();
  ```
- At the documented INSERTION POINT, after `rlimit::apply(&limits)?;`, add:
  ```rust
  fs::apply(&fs_rules)?;
  ```
  Keep the comment noting seccomp comes *after* this (plans 004/005).

**Verify**:
- `cargo build -p guardrail-linux` → exit 0
- `cargo clippy -p guardrail-linux --lib -- -D warnings` → exit 0

### Step 4: Add `read-file` / `write-file` commands to the probe

In `crates/guardrail-linux/src/bin/guardrail-probe.rs`, extend the `match` with:

- `"read-file"`: read `args[2]`; on success exit `0`, on any error exit `3`.
  ```rust
  "read-file" => {
      let path = args.get(2).map(String::as_str).unwrap_or("");
      match std::fs::read(path) {
          Ok(_) => exit(0),
          Err(_) => exit(3),
      }
  }
  ```
- `"write-file"`: write a byte to `args[2]`; on success exit `0`, error exit `3`.
  ```rust
  "write-file" => {
      let path = args.get(2).map(String::as_str).unwrap_or("");
      match std::fs::write(path, b"x") {
          Ok(_) => exit(0),
          Err(_) => exit(3),
      }
  }
  ```
Update the usage string and the doc comment's command list.

**Verify**: `cargo build -p guardrail-linux --bin guardrail-probe` → exit 0.

### Step 5: Integration tests — `filesystem.rs`

Create `crates/guardrail-linux/tests/filesystem.rs`. Tests must validate
**intent** (spec §7): denied by default, allowed when granted, writes blocked
unless write-granted, and the target binary still runs under confinement.

Use a `tempfile::TempDir` for a path you control (don't rely on `/etc/shadow`
permissions, which confound the test with DAC). Skip-guard: if Landlock is not
enforced, the deny-tests can't pass — detect and skip (see helper below).

```rust
use std::process::{Command, Stdio};

use guardrail_core::{NetworkPolicy, SandboxBuilder};
use guardrail_linux::LinuxBackend;
use tempfile::TempDir;

fn probe(args: &[&str]) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_guardrail-probe"));
    c.args(args).stdout(Stdio::null()).stderr(Stdio::null());
    c
}

/// Run the probe under `config`, return whether it exited 0 (allowed).
fn allowed(config: &guardrail_core::SandboxConfig, args: &[&str]) -> bool {
    let mut child = config
        .spawn_with(&LinuxBackend::new(), probe(args))
        .expect("spawn");
    child.wait().expect("wait").success()
}

/// Returns true if Landlock appears to be enforcing on this kernel. Used to skip
/// deny-assertions on unsupported kernels (CI). On this project's dev host
/// (kernel 7.0.8) it returns true.
fn landlock_enforced() -> bool {
    std::fs::read_to_string("/sys/kernel/security/lsm")
        .map(|s| s.split(',').any(|m| m.trim() == "landlock"))
        .unwrap_or(false)
}

#[test]
fn target_binary_runs_under_default_confinement() {
    // The probe itself lives under /usr or the target dir; the default system
    // read dirs plus the binary's own path must let it execute. Grant read on
    // the binary's directory to be safe across `target/` locations.
    let exe = std::path::PathBuf::from(env!("CARGO_BIN_EXE_guardrail-probe"));
    let dir = exe.parent().unwrap().to_path_buf();
    let config = SandboxBuilder::new().allow_read(dir).build();
    assert!(
        allowed(&config, &["echo-env", "PATH"]),
        "the sandboxed binary must be loadable/executable under default rules"
    );
}

#[test]
fn read_is_denied_without_grant_and_allowed_with_grant() {
    if !landlock_enforced() {
        eprintln!("skipping: Landlock not enforced on this kernel");
        return;
    }
    let exe = std::path::PathBuf::from(env!("CARGO_BIN_EXE_guardrail-probe"));
    let exe_dir = exe.parent().unwrap().to_path_buf();

    let tmp = TempDir::new().unwrap();
    let secret = tmp.path().join("secret.txt");
    std::fs::write(&secret, b"top secret").unwrap();
    let secret_s = secret.to_str().unwrap();

    // Denied: only the binary dir is readable, not the temp dir.
    let denied = SandboxBuilder::new().allow_read(&exe_dir).build();
    assert!(
        !allowed(&denied, &["read-file", secret_s]),
        "reading an un-granted path must be denied"
    );

    // Allowed: grant read on the temp dir.
    let granted = SandboxBuilder::new()
        .allow_read(&exe_dir)
        .allow_read(tmp.path())
        .build();
    assert!(
        allowed(&granted, &["read-file", secret_s]),
        "reading a granted path must succeed"
    );
}

#[test]
fn write_is_denied_without_grant_and_allowed_with_write_grant() {
    if !landlock_enforced() {
        eprintln!("skipping: Landlock not enforced on this kernel");
        return;
    }
    let exe = std::path::PathBuf::from(env!("CARGO_BIN_EXE_guardrail-probe"));
    let exe_dir = exe.parent().unwrap().to_path_buf();

    let tmp = TempDir::new().unwrap();
    let target = tmp.path().join("out.txt");
    let target_s = target.to_str().unwrap();

    // Read-only grant on the temp dir → write denied.
    let ro = SandboxBuilder::new()
        .allow_read(&exe_dir)
        .allow_read(tmp.path())
        .build();
    assert!(
        !allowed(&ro, &["write-file", target_s]),
        "writing under a read-only grant must be denied"
    );

    // Write grant → allowed.
    let rw = SandboxBuilder::new()
        .allow_read(&exe_dir)
        .allow_write(tmp.path())
        .build();
    assert!(
        allowed(&rw, &["write-file", target_s]),
        "writing under a write grant must succeed"
    );
}
```

> The `NetworkPolicy` import is unused here; drop it if clippy complains, or keep
> tests minimal. Do not add network policy to these tests — that's plan 004.

**Verify**:
- `cargo test -p guardrail-linux --test filesystem` → all pass (on this host,
  none skip)
- `cargo test -p guardrail-linux` → all prior tests still pass too

## Test plan

- `filesystem.rs` covers: (a) the sandboxed binary still runs under default
  confinement (guards against an over-tight default read set), (b) read denied
  without a grant / allowed with one, (c) write denied under read-only grant /
  allowed under write grant.
- Uses `tempfile::TempDir` for DAC-independent paths and the `guardrail-probe`
  helper for deterministic behavior.
- Skip-guards (`landlock_enforced()`) keep the suite green on kernels without
  Landlock while still asserting fully on supported hosts (this project's dev
  machine and any modern CI image).
- Model after `tests/resource_limits.rs` from plan 002 (same probe pattern).

## Done criteria

Machine-checkable. ALL must hold:

- [ ] `cargo build -p guardrail-linux` exits 0 (with `landlock` resolved)
- [ ] `cargo test -p guardrail-linux --test filesystem` exits 0; on a
      Landlock-enabled kernel all three tests run (none skipped)
- [ ] `cargo test -p guardrail-linux` exits 0 (env + resource + filesystem)
- [ ] `cargo clippy -p guardrail-linux --all-targets -- -D warnings` exits 0
- [ ] `cargo fmt --check` exits 0
- [ ] `guardrail-core` unchanged (`git diff --quiet -- crates/guardrail-core`)
- [ ] `seccomp.rs` does NOT exist and `seccompiler` is NOT a dependency
- [ ] No files outside the in-scope list are modified
- [ ] `plans/README.md` status row for 003 set to DONE

## STOP conditions

Stop and report (do not improvise) if:

- `target_binary_runs_under_default_confinement` fails. That means the default
  `SYSTEM_READ_DIRS` set is insufficient for this distro to load the binary —
  report the failure (and, if you can, the `strace`/error) so the default set
  can be revisited, rather than widening it to `/` (which would gut the sandbox).
- The plan-002 `pre_exec` insertion point is gone or `rlimit::apply` no longer
  precedes it (drift).
- `restrict_self()` returns an `Err` (not just `NotEnforced`) on this host —
  that's a real Landlock failure worth reporting, not something to swallow.
- The `landlock` crate's builder method names differ from this plan and docs.rs
  doesn't clarify the correct chain — report rather than thrashing.
- You find you must change `guardrail-core` or pull in seccomp — scope leak.

## Maintenance notes

- **Default read set (`SYSTEM_READ_DIRS`) is a security/usability tradeoff.**
  Too narrow → programs fail to start; too broad → readable secrets. It
  intentionally excludes `/home`, `/root`, `/tmp`, `/var`, `/proc`, `/sys`,
  `/dev`. If a future change adds one of those to the default, a reviewer must
  scrutinize it (e.g. `/proc` self-info leakage, `/tmp` cross-tenant data).
- **ABI pinning**: pinned to `ABI::V1` for max kernel coverage. If the sandbox
  later needs newer rights (e.g. `Refer` for cross-dir rename in V2, `Truncate`
  in V3, network rules in V4+), bump deliberately and re-test `FullyEnforced`.
- **`pre_exec` ordering**: `fs::apply` must stay *before* the seccomp step that
  plans 004/005 add — Landlock issues its own syscalls (`landlock_*`) that a
  seccomp denylist must not block (a default-allow seccomp filter won't, but
  order-keeping avoids future surprises).
- Landlock cannot report *which* path was denied to the parent; that limitation
  shapes the observability story in plan 006 (FS denials surface only as the
  child's own EACCES, not a parent-visible signal).
</content>
