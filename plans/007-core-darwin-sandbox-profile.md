# Plan 007: Add a Darwin Seatbelt profile permission to `guardrail-core`

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving on. If
> anything in "STOP conditions" occurs, stop and report. When done, update this
> plan's row in `plans/README.md`.
>
> **Drift check (run first)**:
> `jj diff --from 60d299a8a1cb --to @ --stat -- crates/guardrail-core/src/builder.rs crates/guardrail-core/src/config.rs crates/guardrail-linux/src/lib.rs`
> If any in-scope file changed since this plan was written, compare the excerpts
> below against the live code before proceeding. On a mismatch, STOP.

## Status

- **Priority**: P1
- **Effort**: S
- **Risk**: LOW (additive API field and builder method)
- **Depends on**: plans/001 through plans/006 are already DONE
- **Category**: direction / platform support
- **Planned at**: commit `60d299a8a1cb`, 2026-06-23

## Why this matters

The macOS backend needs a way for callers to provide an explicit Apple Seatbelt
`.sb` profile. The user requested this as a "darwin sandbox profile" permission:
it stores a path to a macOS Seatbelt profile, is ignored by non-macOS backends,
and is consumed only by the macOS backend. Putting the path in `guardrail-core`
keeps it declarative like the existing filesystem, network, IPC, resource, and
environment policies.

## Current state

- `crates/guardrail-core/src/config.rs:31-43` defines `SandboxConfig` with
  `fs`, `network`, `ipc`, `limits`, and `env`, but no platform-specific policy
  fields.
- `crates/guardrail-core/src/builder.rs:30-35` defines `SandboxBuilder` with the
  same fields. `build()` at `builder.rs:111-120` constructs `SandboxConfig`.
- `crates/guardrail-linux/src/lib.rs:33-38` reads only `limits`, `fs`, and the
  seccomp-relevant policies. Linux must continue to ignore the new Darwin field.
- `spec.md:108-111` says the macOS backend is Seatbelt plus `setrlimit`.
- Existing style: builder methods take `self` by value and return `Self`, e.g.
  `allow_read` at `builder.rs:44-48` and `network` at `builder.rs:62-66`.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Core tests | `cargo test -p guardrail-core` | exit 0, all tests pass |
| Linux no-op regression | `cargo test -p guardrail-linux` | exit 0, all tests pass or existing host-specific skips only |
| Workspace lint | `cargo clippy --workspace --all-targets -- -D warnings` | exit 0 |
| Format check | `cargo fmt --check` | exit 0 |

## Scope

**In scope**:
- `crates/guardrail-core/src/config.rs`
- `crates/guardrail-core/src/builder.rs`
- `crates/guardrail-core/src/lib.rs` only if a new public type is needed; the
  recommended design below does not need one
- `plans/README.md` status row

**Out of scope**:
- Do not modify `crates/guardrail-linux/src/lib.rs`; the new field is a no-op on
  Linux by being unread there.
- Do not add the macOS backend crate here; that is plan 009.
- Do not parse or validate `.sb` profile contents in `guardrail-core`; core only
  stores the path.

## Git workflow

Repo uses **jj** colocated with git. Do not commit, branch, push, or open a PR
unless the operator explicitly asks. Leave changes in the working copy.

## Steps

### Step 1: Add the config field

In `crates/guardrail-core/src/config.rs`, import `PathBuf` alongside
`BTreeMap`, then add this public field to `SandboxConfig`:

```rust
/// macOS-only Seatbelt profile path. Non-Darwin backends ignore this field.
///
/// When set, the macOS backend loads this `.sb` profile and applies it instead
/// of generating a profile from the portable `fs`/`network`/`ipc` policies.
pub darwin_sandbox_profile: Option<PathBuf>,
```

Keep the existing derived traits: `Debug`, `Clone`, `PartialEq`, and `Eq`.

**Verify**: `cargo test -p guardrail-core` should fail at this point only because
`SandboxConfig` construction is missing the new field. If it fails for an
unrelated reason, STOP.

### Step 2: Add the builder method

In `crates/guardrail-core/src/builder.rs`:

1. Add a private builder field:
   ```rust
   darwin_sandbox_profile: Option<PathBuf>,
   ```
2. Add a builder method near the other policy methods:
   ```rust
   /// Set a macOS Seatbelt `.sb` profile path.
   ///
   /// This is ignored by non-Darwin backends. On macOS it overrides generated
   /// Seatbelt profile generation.
   pub fn darwin_sandbox_profile(mut self, path: impl Into<PathBuf>) -> Self {
       self.darwin_sandbox_profile = Some(path.into());
       self
   }
   ```
3. In `build()`, pass the field into `SandboxConfig`.
4. Update the doc example only if it stays readable; do not make the main
   example macOS-specific.

**Verify**: `cargo test -p guardrail-core` exits 0 or reports only tests that now
need the assertions from Step 3.

### Step 3: Add core tests for default and last-call behavior

Update `crates/guardrail-core/src/builder.rs` tests:

- In `default_config_denies_everything`, assert:
  ```rust
  assert_eq!(config.darwin_sandbox_profile, None);
  ```
- Add a test:
  ```rust
  #[test]
  fn darwin_sandbox_profile_last_call_wins() {
      let config = SandboxBuilder::new()
          .darwin_sandbox_profile("/tmp/first.sb")
          .darwin_sandbox_profile("/tmp/second.sb")
          .build();
      assert_eq!(
          config.darwin_sandbox_profile,
          Some(PathBuf::from("/tmp/second.sb"))
      );
  }
  ```

**Verify**: `cargo test -p guardrail-core` exits 0.

### Step 4: Confirm Linux treats the permission as a no-op

Do not add any Linux code to consume the new field. Run the Linux tests to prove
that adding this platform-specific policy did not alter Linux behavior.

**Verify**:
- `cargo test -p guardrail-linux` exits 0 on this Linux host.
- `rg -n "darwin_sandbox_profile" crates/guardrail-linux` returns no matches.

## Test plan

- Core unit coverage lives in `crates/guardrail-core/src/builder.rs`.
- Linux no-op coverage is the existing `guardrail-linux` integration suite plus
  the `rg` check above showing Linux never reads the Darwin field.

## Done criteria

- [ ] `cargo test -p guardrail-core` exits 0.
- [ ] `cargo test -p guardrail-linux` exits 0 on Linux, subject only to existing
      host-specific skips already present in the suite.
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` exits 0.
- [ ] `cargo fmt --check` exits 0.
- [ ] `rg -n "darwin_sandbox_profile" crates/guardrail-linux` returns no matches.
- [ ] No files outside the in-scope list are modified except `plans/README.md`.

## STOP conditions

Stop and report if:

- The live `SandboxConfig` or `SandboxBuilder` shape no longer matches the
  excerpts in "Current state".
- Adding the field requires changing the `Backend` trait signature.
- Linux needs code changes to preserve existing behavior. That would mean the
  field is not actually a no-op on non-Darwin platforms and the design needs
  review.

## Maintenance notes

The macOS backend in plan 009 must read this field. Other future backends should
ignore it unless they intentionally implement Darwin Seatbelt compatibility.
Reviewers should check that this field stays data-only in `guardrail-core`; no
file IO or platform-specific parsing belongs there.

