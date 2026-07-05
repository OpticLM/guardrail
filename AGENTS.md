# AGENTS.md

## Philosophy

**KISS.** No glue code, no over-engineering. Each layer should be a faithful, thin implementation of its single intent — describe a policy, apply it, spawn the child, explain a failure. When a change tempts you to add indirection, abstraction, or a "flexible" extension point you weren't asked for, resist it.

**Ground every claim about library behavior.** Do not guess other crates behaves. When unsure, verify with the **context7** or **docs-rs** MCP servers before writing or asserting behavior. Read the crate's actual `src` and its docs rather than recalling from memory.

**Ask, don't assume.** When an instruction is ambiguous or a decision could go several ways, ask the user. Do not silently pick the approach *you* think is right and proceed. This applies to API shape, feature scope, and platform behavior.

## Repository

`guardrail` is a cross-platform process-sandbox library. A single declarative policy (`guardrail-core`) is applied by per-OS backends (`guardrail-linux`, `guardrail-macos`, `guardrail-windows`) and exposed to Node via `guardrail-napi`.

VCS is **jj (Jujutsu)** colocated with git. Use `jj` for inspection (`jj status`, `jj diff`, `jj log`), not `git`. There is a jj VCS skill for agents as reference.

## Commands

- In `crates/guardrail-napi`, use pnpm as the package manager, not npm.
- CI currently builds the napi binary for all six targets and runs `pnpm test` on the host targets.

## Architecture

**`guardrail-core` (platform-agnostic).** Defines all the public types and the contract backends implement.

**Platform backends.** Each implements `Backend` and applies confinement. Linux and macOS do all confinement inside `std::process::Command::pre_exec` (after fork, before exec); Windows launches the child suspended, installs policy (Job Object + AppContainer + ACL), then resumes.

- `guardrail-linux` — Landlock (fs), seccomp-BPF (network + IPC), `setrlimit` (resources), `NO_NEW_PRIVS` first. Seccomp is applied **last** so its filter doesn't interfere with Landlock's setup syscalls.
- `guardrail-macos` — Seatbelt (`painless-belt`) + `setrlimit`. Profile generation is platform-independent and unit-tested on Linux. Seatbelt uses `(deny default)`, so a real binary often needs runtime grants (dyld paths, sysctl names) beyond the portable policy; the `darwin_sandbox_profile` builder escape hatch + the crate-level tips doc are the answer — see `guardrail-macos/src/lib.rs`. `IpcPolicy` is effectively a no-op on macOS.
- `guardrail-windows` — AppContainer (per-run SID, fs/network), Job Object (process tree dies with the sandbox), ACL grants are *additive* (only ever append ACEs). `IpcPolicy` is a documented no-op on Windows.

**`guardrail-napi` (Node bindings).** One `spawn(command, args?, options?)` function; `options` mirrors `SandboxConfig` fields (camelCase, see `SpawnOptions`). The backend is selected at **build time via `cfg(target_os)` (`PlatformBackend`)** — each published binary targets exactly one OS. `wait()` runs on the libuv threadpool via `WaitTask`; diagnostics come from the backend's `Backend::explain` override (no separate `explain` import to keep in sync). `stdio` is inherited; output capture is not yet supported.

## Testing conventions

- Every platform crate ships a `guardrail-<os>-probe` binary (`src/bin/`), a deterministic helper that exits `0` (allowed), `3` (denied — the expected sandboxed result), or `2` (usage error). Integration tests in `crates/guardrail-*/tests/` spawn the probe under a policy and assert the exit code. Locate the probe via the `CARGO_BIN_EXE_guardrail-<os>-probe` env var Cargo sets for tests — reuse this pattern when adding integration tests rather than depending on arbitrary system binaries.
- Platform-backend code is `#[cfg(target_os = ...)]`-gated and the crates compile on every platform (the non-target `spawn` returns `Error::Unsupported`), so the whole workspace builds and unit-tests anywhere, while confinement behavior is only exercised on its native target.