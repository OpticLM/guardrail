# Plan 010: Validate the macOS backend on a real macOS host

> **Executor instructions**: Follow this plan step by step on a macOS machine.
> Run every verification command and confirm the expected result before moving
> on. If anything in "STOP conditions" occurs, stop and report. When done,
> update this plan's row in `plans/README.md`.
>
> **Drift check (run first)**:
> `jj diff --from 60d299a8a1cb --to @ --stat -- crates/guardrail-core crates/guardrail-macos Cargo.toml`
> If plans 007 through 009 have not been executed, run them first. This plan is
> last because it requires macOS; it is not expected to pass on the Linux host.

## Status

- **Priority**: P2
- **Effort**: M
- **Risk**: MED (runtime validation may reveal Seatbelt profile syntax fixes)
- **Depends on**: plans/007, plans/008, plans/009
- **Category**: tests / platform support
- **Planned at**: commit `60d299a8a1cb`, 2026-06-23

## Why this matters

Plans 007 through 009 are intentionally executable on Linux, but Seatbelt can
only be proven on macOS. This plan adds macOS-only integration coverage and uses
that feedback to fix any profile syntax, operation names, or runtime ordering
issues. The user explicitly said there is no macOS environment here, so this is
the final validation plan rather than a prerequisite for the Linux-executable
work.

## Current state

Expected after plans 007 through 009:

- `guardrail-core::SandboxConfig` has `darwin_sandbox_profile: Option<PathBuf>`.
- `guardrail-macos` exists and exposes `MacosBackend`.
- `guardrail-macos` uses `painless-belt = 0.2.3`.
- Generated profiles start from `(version 1)` and `(deny default)`, then add
  rules from `FsAccess` and `NetworkPolicy`.
- Custom `.sb` profile files are read in the parent and applied on macOS before
  `exec`.

## Commands you will need

Run these on macOS:

| Purpose | Command | Expected on success |
|---|---|---|
| Confirm host | `rustc -vV` | `host:` contains `apple-darwin` |
| Build macOS backend | `cargo build -p guardrail-macos` | exit 0 |
| Test macOS backend | `cargo test -p guardrail-macos` | exit 0 |
| Workspace test | `cargo test --workspace` | exit 0, except Linux-only tests may be cfg/skipped |
| Workspace lint | `cargo clippy --workspace --all-targets -- -D warnings` | exit 0 |
| Format check | `cargo fmt --check` | exit 0 |

## Scope

**In scope**:
- `crates/guardrail-macos/src/profile.rs`
- `crates/guardrail-macos/src/seatbelt.rs`
- `crates/guardrail-macos/src/rlimit.rs`
- `crates/guardrail-macos/src/lib.rs`
- `crates/guardrail-macos/tests/*` (create as needed)
- `crates/guardrail-macos/src/bin/*` (create a probe only if integration tests
  need deterministic child behavior)
- `plans/README.md` status row

**Out of scope**:
- Do not change `guardrail-linux`.
- Do not change core API names unless the macOS implementation is impossible
  with the plan 007 API.
- Do not add broad hidden filesystem grants. Like Linux, callers must explicitly
  grant the paths needed to execute a binary and load its runtime dependencies.

## Git workflow

Repo uses **jj** colocated with git. Do not commit, branch, push, or open a PR
unless the operator explicitly asks. Leave changes in the working copy.

## Steps

### Step 1: Confirm the host and baseline build

Run:

```sh
rustc -vV
cargo build -p guardrail-macos
cargo test -p guardrail-macos
```

Expected:

- `rustc -vV` reports an Apple Darwin host.
- Build succeeds.
- Existing unit tests pass.

If the build fails because a Seatbelt operation name is invalid only at runtime,
continue to Step 2. If it fails to compile due to missing `libc` constants or a
changed `painless-belt` API, STOP and report.

### Step 2: Add a custom-profile integration test

Create a macOS-only integration test file, for example
`crates/guardrail-macos/tests/custom_profile.rs`, guarded with:

```rust
#![cfg(target_os = "macos")]
```

Test intent:

- Create a temp directory with `secret.txt`.
- Write a custom `.sb` profile that starts with `(version 1)` and `(allow default)`,
  then denies file reads for that exact secret path.
- Build config:
  ```rust
  let config = SandboxBuilder::new()
      .darwin_sandbox_profile(profile_path)
      .build();
  ```
- Spawn `/bin/cat <secret>` through `MacosBackend::new()`.
- Assert the child exits unsuccessfully.

This test proves the `.sb` path is loaded and applied without needing to solve
generated default-deny runtime grants first.

**Verify**: `cargo test -p guardrail-macos --test custom_profile` exits 0 on
macOS.

### Step 3: Add generated-profile smoke coverage

Add a second macOS-only test, for example
`crates/guardrail-macos/tests/generated_profile.rs`.

Use an executable with minimal dependencies, usually `/usr/bin/true` or
`/bin/echo`. Build a config with explicit read and execute grants needed for
that program and the dynamic loader. Model the Linux test helper's approach in
`crates/guardrail-linux/tests/common/mod.rs`: discover runtime libraries using
macOS tooling (`otool -L <binary>`) and grant their parent directories.

Test cases:

- With explicit read/execute runtime grants, the program exits successfully.
- Without the execute grant for the target program, spawning or execution fails.
- If `NetworkPolicy::Deny` is the default, a small probe that creates a TCP
  socket should fail under the generated profile. Create a probe binary only if
  invoking system tools would make the test flaky.

**Verify**: `cargo test -p guardrail-macos --test generated_profile` exits 0 on
macOS.

### Step 4: Fix macOS-only issues found by the tests

Expected fix categories:

- If `process-exec` or another generated operation name is wrong, update
  `crates/guardrail-macos/src/profile.rs` and keep the test that caught it.
- If Seatbelt rejects escaped `subpath` strings, fix the escaping helper in
  `profile.rs` and add tests for paths with spaces, quotes, and backslashes.
- If Seatbelt must be applied before or after rlimits differently, adjust
  `crates/guardrail-macos/src/lib.rs` and explain the ordering in a comment.

Do not paper over failures with `(allow default)` in generated profiles. The
custom-profile test may use `(allow default)` because its purpose is to prove
that user-supplied `.sb` files are loaded.

**Verify** after any fix:
- `cargo test -p guardrail-macos` exits 0 on macOS.
- `cargo clippy -p guardrail-macos --all-targets -- -D warnings` exits 0.
- `cargo fmt --check` exits 0.

### Step 5: Run full workspace gates on macOS

Run:

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```

Expected:

- All macOS-capable tests pass.
- Linux-only tests are cfg-gated or skipped appropriately; do not rewrite Linux
  tests to force them to pass on macOS.

## Test plan

This plan creates the first native macOS integration tests. The highest-priority
coverage is the custom `.sb` profile path because that was explicitly requested.
Generated-profile tests are next and should focus on observable behavior, not
internal implementation order.

## Done criteria

- [ ] `rustc -vV` confirms an Apple Darwin host.
- [ ] A macOS-only integration test proves `.darwin_sandbox_profile(<path>)`
      loads and applies a `.sb` profile.
- [ ] Generated-profile macOS smoke tests pass or produce a documented BLOCKED
      status with exact Seatbelt syntax/API evidence.
- [ ] `cargo test -p guardrail-macos` exits 0 on macOS.
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` exits 0 on macOS,
      except for pre-existing non-macOS target issues explicitly recorded in
      `plans/README.md`.
- [ ] `cargo fmt --check` exits 0.

## STOP conditions

Stop and report if:

- You are not on a macOS host.
- Apple has removed or disabled the private Seatbelt API needed by
  `painless-belt`.
- Making generated profiles work requires hidden broad filesystem grants.
- You need to change the public core API from plan 007.

## Maintenance notes

Seatbelt is effectively a process-once API. Keep native Seatbelt tests as
integration tests with one sandbox application per test process where necessary.
Future macOS policy work should add behavioral tests here before widening
generated SBPL.
