# Plan 009: Implement the `guardrail-macos` Backend with Seatbelt and rlimits

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving on. If
> anything in "STOP conditions" occurs, stop and report. When done, update this
> plan's row in `plans/README.md`.
>
> **Drift check (run first)**:
> `jj diff --from 60d299a8a1cb --to @ --stat -- Cargo.toml crates/guardrail-core/src/config.rs crates/guardrail-macos`
> This plan assumes plans 007 and 008 are complete. If `guardrail-macos` does
> not exist yet, execute plan 008 first.

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: MED (native process sandboxing and pre-exec code)
- **Depends on**: plans/007-core-darwin-sandbox-profile.md,
  plans/008-macos-seatbelt-profile-generation.md
- **Category**: direction / platform support
- **Planned at**: commit `60d299a8a1cb`, 2026-06-23

## Why this matters

This plan adds the actual macOS backend implementation. It should match the
existing backend contract: `SandboxConfig::spawn_with` scrubs the environment,
then the platform backend applies resource limits and OS confinement before
`exec`. In addition, the new Darwin Seatbelt profile path from plan 007 is
loaded on macOS and ignored elsewhere.

The selected crate is **`painless-belt = 0.2.3`**. It is MIT-licensed and exposes
a direct Rust wrapper around Apple's `sandbox_init(profile, flags, errorbuf)` as
`painless_belt::ffi::sandbox_init`, which fits this repo's in-process backend
style. Other MIT crates were considered but rejected: `heimdall-macos-sandbox`,
`sbexec`, and `ai-jail` primarily plan or shell out through `/usr/bin/sandbox-exec`,
while `sandbox-host-macos` brings a separate `cross-sandbox-core` policy model.

## Current state

- `crates/guardrail-linux/src/lib.rs:32-74` is the backend pattern to mirror:
  clone owned config data, install a `pre_exec` closure, apply resource limits,
  apply OS confinement, then spawn and wrap the child.
- `crates/guardrail-linux/src/rlimit.rs:1-35` shows the current `setrlimit`
  implementation.
- `painless-belt 0.2.3` exposes `painless_belt::ffi::sandbox_init(profile, flags)`
  and validates interior NUL bytes before calling Apple's API. Its crate license
  is MIT.
- Plan 008 now generates escaped SBPL strings directly because `painless-belt`
  exposes `sandbox_init`, not `sandbox_init_with_parameters`.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Build macOS crate | `cargo build -p guardrail-macos` | exit 0 on Linux |
| Test macOS crate | `cargo test -p guardrail-macos` | exit 0 on Linux |
| Workspace test | `cargo test --workspace` | exit 0 on Linux |
| Workspace lint | `cargo clippy --workspace --all-targets -- -D warnings` | exit 0 |
| Format check | `cargo fmt --check` | exit 0 |

## Scope

**In scope**:
- `crates/guardrail-macos/Cargo.toml`
- `crates/guardrail-macos/src/lib.rs`
- `crates/guardrail-macos/src/rlimit.rs` (create)
- `crates/guardrail-macos/src/seatbelt.rs` (create)
- `crates/guardrail-macos/src/profile.rs` only for visibility helpers needed by
  `seatbelt.rs`
- `plans/README.md` status row

**Out of scope**:
- Do not modify `guardrail-linux`.
- Do not change the `Backend` trait.
- Do not add a top-level facade crate.
- Do not require macOS runtime tests to pass on this Linux host; plan 010 covers
  macOS validation.

## Git workflow

Repo uses **jj** colocated with git. Do not commit, branch, push, or open a PR
unless the operator explicitly asks. Leave changes in the working copy.

## Steps

### Step 1: Add the Seatbelt binding crate

Add this target-specific dependency to `crates/guardrail-macos/Cargo.toml`:

```toml
[target.'cfg(target_os = "macos")'.dependencies]
painless-belt = "0.2.3"
```

Keep `guardrail-core` and `libc` as normal dependencies. The target-specific
dependency keeps Linux builds simple while still using the crate on macOS.

**Verify**: `cargo build -p guardrail-macos` exits 0 on Linux.

### Step 2: Add resource-limit support

Create `crates/guardrail-macos/src/rlimit.rs` by copying the shape of
`guardrail-linux/src/rlimit.rs`, with these notes:

- Use `guardrail_core::ResourceLimits`.
- Apply `RLIMIT_AS`, `RLIMIT_CPU`, and `RLIMIT_NPROC` when the corresponding
  fields are `Some`.
- Use `libc::setrlimit` and return `std::io::Result<()>`.
- Keep the module private.

`libc` defines these constants for Apple targets, confirmed in
`libc-0.2.186/src/unix/bsd/apple/mod.rs:2517-2525`.

**Verify**: `cargo build -p guardrail-macos` exits 0 on Linux.

### Step 3: Add Seatbelt profile resolution and application

Create `crates/guardrail-macos/src/seatbelt.rs`:

- Define an internal owned struct, or reuse `profile::SeatbeltProfile`, with:
  - `source: String`
- Add `pub(crate) fn resolve(config: &SandboxConfig) -> Result<SeatbeltProfile, Error>`:
  - If `config.darwin_sandbox_profile` is `Some(path)`, read the file in the
    parent with `std::fs::read_to_string(path)`.
  - Validate the string contains no `'\0'`. On failure return
    `Error::confinement("seatbelt-profile", io::Error::new(ErrorKind::InvalidData, "..."))`.
  - Return that source.
  - If the field is `None`, call `profile::build(config)`, then validate the
    generated source for interior NUL bytes.
- Add `#[cfg(target_os = "macos")] pub(crate) fn apply(profile: &SeatbeltProfile) -> Result<(), Error>`:
  - Call `painless_belt::ffi::sandbox_init(&profile.source, 0)`.
  - Map any error to `Error::confinement("seatbelt", std::io::Error::other(err.to_string()))`.
- Add `#[cfg(not(target_os = "macos"))] pub(crate) fn apply(...) -> Result<(), Error>` that
  returns `Error::Unsupported("Seatbelt is only available on macOS".into())`.

Do not read the `.sb` file inside `pre_exec`; file IO belongs in the parent so
errors are deterministic and can be returned normally.

**Verify**: `cargo test -p guardrail-macos` exits 0 on Linux.

### Step 4: Implement `MacosBackend`

Update `crates/guardrail-macos/src/lib.rs`:

- Export `pub struct MacosBackend { _private: () }`, matching
  `LinuxBackend`'s style.
- Add `new() -> Self`.
- Implement `guardrail_core::Backend`.
- For non-macOS targets, `spawn` returns:
  ```rust
  Err(Error::Unsupported(
      "guardrail-macos backend only supports target_os = \"macos\"".into(),
  ))
  ```
- For macOS targets:
  1. Read/resolve the Seatbelt profile in the parent:
     `let seatbelt_profile = seatbelt::resolve(config)?;`
  2. Copy limits: `let limits = config.limits;`
  3. Install a `pre_exec` closure:
     - `rlimit::apply(&limits)?;`
     - `seatbelt::apply(&seatbelt_profile).map_err(std::io::Error::other)?;`
  4. Spawn the command and wrap it in `SandboxChild`.

Keep the order as **rlimits first, Seatbelt second**. Seatbelt is irreversible
and may restrict syscalls/file access needed by later setup.

**Verify**:
- `cargo build -p guardrail-macos` exits 0 on Linux.
- `cargo test -p guardrail-macos` exits 0 on Linux.

### Step 5: Add Linux-host tests for non-macOS behavior

In `crates/guardrail-macos/src/lib.rs` tests, under
`#[cfg(not(target_os = "macos"))]`, assert that spawning through
`MacosBackend::new()` returns `Error::Unsupported`.

This is also the no-op proof for other platforms: the Darwin profile path can be
stored in core config, but non-macOS execution through this backend does not try
to load or apply Seatbelt.

**Verify**: `cargo test -p guardrail-macos` exits 0 on Linux.

### Step 6: Run workspace gates

Run the full Linux-host gates after the crate compiles.

**Verify**:
- `cargo test --workspace` exits 0.
- `cargo clippy --workspace --all-targets -- -D warnings` exits 0.
- `cargo fmt --check` exits 0.

## Test plan

- Linux-host tests verify the crate compiles and returns `Unsupported` on
  non-macOS.
- Existing profile-generation tests from plan 008 continue to cover generated
  policy text.
- Native Seatbelt enforcement tests are intentionally deferred to plan 010
  because this host is Linux.

## Done criteria

- [ ] `guardrail-macos` exposes `MacosBackend::new()`.
- [ ] On non-macOS, `MacosBackend::spawn` returns `Error::Unsupported`.
- [ ] On macOS, `MacosBackend::spawn` resolves the profile in the parent, applies
      rlimits and Seatbelt in `pre_exec`, then spawns.
- [ ] The custom `.sb` profile path from plan 007 overrides generated profile
      generation.
- [ ] Profile strings are checked for interior NUL bytes before calling
      `painless_belt::ffi::sandbox_init`.
- [ ] Linux-host workspace test, clippy, and format gates pass.

## STOP conditions

Stop and report if:

- `painless-belt` no longer exposes `painless_belt::ffi::sandbox_init`.
- Applying Seatbelt requires changing the `Backend` trait or replacing
  `std::process::Command`.
- Clippy forces broad source changes outside `guardrail-macos`.
- The implementation needs to shell out to `sandbox-exec`; that would contradict
  the in-process backend direction and should be reviewed by the operator.

## Maintenance notes

Reviewers should scrutinize all code that runs in `pre_exec`. It must avoid
panics and should do as much work as possible in the parent. If future work adds
parameterized custom `.sb` profiles, keep the current raw-file behavior as the
simple default and add a separate typed API rather than overloading the path.
