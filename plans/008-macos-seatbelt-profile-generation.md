# Plan 008: Add generated macOS Seatbelt profile support

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving on. If
> anything in "STOP conditions" occurs, stop and report. When done, update this
> plan's row in `plans/README.md`.
>
> **Drift check (run first)**:
> `jj diff --from 60d299a8a1cb --to @ --stat -- Cargo.toml crates/guardrail-core/src/config.rs`
> This plan assumes plan 007 has added `SandboxConfig::darwin_sandbox_profile`.
> If it has not, execute plan 007 first.

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: MED (Seatbelt profile generation is security-sensitive)
- **Depends on**: plans/007-core-darwin-sandbox-profile.md
- **Category**: direction / platform support
- **Planned at**: commit `60d299a8a1cb`, 2026-06-23

## Why this matters

The macOS backend needs two profile sources: a caller-provided `.sb` file from
plan 007, and a generated profile from the portable `SandboxConfig` policies
when no custom profile is set. This plan creates the `guardrail-macos` crate and
implements only the platform-independent profile generation and tests. It is
safe to execute on Linux because it does not call Seatbelt.

## Current state

- Root `Cargo.toml:1-16` has workspace members `guardrail-core` and
  `guardrail-linux`; there is no `guardrail-macos` crate.
- `spec.md:108-111` calls for macOS Seatbelt plus `setrlimit`.
- `spec.md:115-130` defines the same filesystem, network, and IPC policy intent
  already represented by `FsAccess`, `NetworkPolicy`, and `IpcPolicy`.
- Existing Linux plans deliberately avoided wrapper binaries and use in-process
  confinement. Keep that direction for macOS too.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Build new crate | `cargo build -p guardrail-macos` | exit 0 on Linux |
| Test profile generation | `cargo test -p guardrail-macos` | exit 0 on Linux |
| Workspace test | `cargo test --workspace` | exit 0 on Linux |
| Workspace lint | `cargo clippy --workspace --all-targets -- -D warnings` | exit 0 |
| Format check | `cargo fmt --check` | exit 0 |

## Scope

**In scope**:
- `Cargo.toml`
- `crates/guardrail-macos/Cargo.toml` (create)
- `crates/guardrail-macos/src/lib.rs` (create)
- `crates/guardrail-macos/src/profile.rs` (create)
- `plans/README.md` status row

**Out of scope**:
- Do not call native Seatbelt APIs in this plan.
- Do not implement `Backend` yet; that is plan 009.
- Do not change Linux behavior.
- Do not try to perfectly solve macOS IPC in this Linux-executable plan. Keep a
  conservative generated profile and leave runtime validation to plan 010.

## Git workflow

Repo uses **jj** colocated with git. Do not commit, branch, push, or open a PR
unless the operator explicitly asks. Leave changes in the working copy.

## Steps

### Step 1: Create the crate skeleton

Update root `Cargo.toml`:

```toml
members = [
    "crates/guardrail-core",
    "crates/guardrail-linux",
    "crates/guardrail-macos",
]
```

Add `crates/guardrail-macos/Cargo.toml`:

```toml
[package]
name = "guardrail-macos"
description = "macOS backend for the guardrail sandbox (Seatbelt + setrlimit)."
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true

[dependencies]
guardrail-core.workspace = true
libc.workspace = true
```

Add `crates/guardrail-macos/src/lib.rs`:

```rust
//! macOS backend support for `guardrail`.
//!
//! Profile generation is platform-independent and tested on Linux. Native
//! Seatbelt application is added in plan 009.

mod profile;

#[cfg(test)]
mod tests {
    use guardrail_core::SandboxBuilder;

    #[test]
    fn crate_smoke_test_builds_a_default_config() {
        let config = SandboxBuilder::new().build();
        assert!(config.fs.is_empty());
    }
}
```

**Verify**: `cargo build -p guardrail-macos` exits 0 on Linux.

### Step 2: Implement `profile.rs`

Create `crates/guardrail-macos/src/profile.rs` with an internal representation
that can later be passed to the native Seatbelt binding:

```rust
use guardrail_core::{FsAccess, IpcPolicy, NetworkPolicy, SandboxConfig};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SeatbeltProfile {
    pub(crate) source: String,
}

pub(crate) fn build(config: &SandboxConfig) -> SeatbeltProfile {
    let mut source = String::from("(version 1)\n(deny default)\n");

    for rule in &config.fs {
        match rule {
            FsAccess::Read(path) => {
                let path = sbpl_string(path);
                source.push_str(&format!(
                    "(allow file-read* (subpath \"{path}\"))\n"
                ));
            }
            FsAccess::Write(path) => {
                let path = sbpl_string(path);
                source.push_str(&format!(
                    "(allow file-read* file-write* (subpath \"{path}\"))\n"
                ));
            }
            FsAccess::Execute(path) => {
                let path = sbpl_string(path);
                source.push_str(&format!(
                    "(allow file-read* process-exec (subpath \"{path}\"))\n"
                ));
            }
        }
    }

    match config.network {
        NetworkPolicy::Deny => {}
        NetworkPolicy::OutboundOnly => {
            source.push_str("(allow network-outbound)\n");
        }
        NetworkPolicy::Full => {
            source.push_str("(allow network*)\n");
        }
    }

    match config.ipc {
        IpcPolicy::Strict => {}
        IpcPolicy::Relaxed => {
            // Keep this intentionally narrow until plan 010 validates the exact
            // Seatbelt operations on macOS. The custom `.sb` profile path is
            // the escape hatch for workloads that need more IPC.
        }
    }

    SeatbeltProfile { source }
}

fn sbpl_string(path: &std::path::Path) -> String {
    path.display()
        .to_string()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}
```

Rationale:

- Escape backslashes and double quotes before placing paths in SBPL string
  literals. The chosen non-EUPL binding in plan 009 (`painless-belt`) exposes
  `sandbox_init(profile, flags)`, not `sandbox_init_with_parameters`, so tests
  must cover escaping instead of relying on parameters.
- `Write` grants read+write, matching the current Linux contract.
- `Execute` grants `file-read*` and `process-exec`; plan 010 validates and fixes
  exact Seatbelt operation names on macOS if necessary.
- `IpcPolicy::Strict` adds nothing because `(deny default)` is already the
  strict stance. `Relaxed` remains intentionally conservative until macOS
  validation; users can provide a custom `.sb` profile for finer IPC needs.

**Verify**: `cargo build -p guardrail-macos` exits 0.

### Step 3: Add profile generation tests

Add tests in `crates/guardrail-macos/src/profile.rs` under `#[cfg(test)]`:

- Default config produces `(version 1)` and `(deny default)`, with no extra
  allow rules.
- `allow_read("/tmp/in")` emits one `file-read*` rule with `(subpath "/tmp/in")`.
- `allow_write("/tmp/work")` emits `file-read* file-write*`.
- `allow_execute("/tmp/bin")` emits `process-exec`.
- `NetworkPolicy::Deny` emits no `network` rule.
- `NetworkPolicy::OutboundOnly` emits `network-outbound`.
- `NetworkPolicy::Full` emits `network*`.
- A path containing a double quote is escaped as `\"`.
- A path containing a backslash is escaped as `\\`.

Use the existing style from core tests: direct assertions on data and substrings,
not snapshots.

**Verify**: `cargo test -p guardrail-macos` exits 0 on Linux.

### Step 4: Confirm workspace compatibility

Run the full Linux-host gates.

**Verify**:
- `cargo test --workspace` exits 0 on Linux.
- `cargo clippy --workspace --all-targets -- -D warnings` exits 0.
- `cargo fmt --check` exits 0.

## Test plan

This plan adds pure Rust unit tests for generated profile text and path escaping.
It deliberately does not test native Seatbelt enforcement; plan 010 does that on
macOS.

## Done criteria

- [ ] `guardrail-macos` is a workspace member.
- [ ] `cargo test -p guardrail-macos` exits 0 on Linux.
- [ ] Profile tests cover filesystem grants and network levels.
- [ ] No macOS-only APIs are called in this plan.
- [ ] Workspace test, clippy, and format gates pass on Linux.

## STOP conditions

Stop and report if:

- Plan 007 has not added `SandboxConfig::darwin_sandbox_profile`.
- The project owner rejects generated profiles and wants the macOS backend to
  require custom `.sb` files only.
- Clippy or tests require changing `guardrail-core` or `guardrail-linux` beyond
  normal compile fixes caused by adding the new workspace member.

## Maintenance notes

The profile generator is security-sensitive: avoid broad default allows. If a
future macOS validation discovers an operation name is wrong, fix the generated
profile and add a targeted macOS test in plan 010 rather than widening to
`(allow default)`.
