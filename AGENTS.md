# AGENTS.md

## Philosophy

**KISS.** No glue code, no over-engineering. Each layer should be a faithful, thin implementation of its single intent — describe a policy, apply it, spawn the child. When a change tempts you to add indirection, abstraction, or a "flexible" extension point you weren't asked for, resist it.

**Ground every claim about library behavior.** Do not guess other crates behaves. When unsure, verify with the **context7** or **docs-rs** MCP servers before writing or asserting behavior. Read the crate's actual `src` and its docs rather than recalling from memory.

**Ask, don't assume.** When an instruction is ambiguous or a decision could go several ways, ask the user. Do not silently pick the approach *you* think is right and proceed. This applies to API shape, feature scope, and platform behavior.

## Repository

`guardrail` is a cross-platform process-sandbox library. A single declarative policy (`guardrail-core`) is applied by per-OS backends (`guardrail-linux`, `guardrail-macos`, `guardrail-windows`), selected for Rust users by the `guardrail` facade crate, and exposed to Node via `guardrail-napi`.

VCS is **jj (Jujutsu)** colocated with git. Use `jj` for inspection (`jj status`, `jj diff`, `jj log`), not `git`. There is a jj VCS skill for agents as reference.

## Commit messages

Write commit messages in **scoped commits** form (https://scopedcommits.com/): the scope comes first, before the colon, then the description.

```
<scope>: <description>

[optional body]
[optional trailer(s)]
```

- **No Conventional Commits type prefixes.** The token before the colon is the scope, not a type — never `feat:`, `fix:`, `chore:`, `refactor:`. Write `core: remove SandboxBuilder`, not `refactor(core): remove SandboxBuilder`.
- **Scope is the area touched.** Prefer a crate or concern name: `core`, `linux`, `macos`, `windows`, `napi`, `facade` (the `guardrail` facade crate), `ci`, `docs`. A narrower sub-scope is fine when it's more informative than the crate (e.g. `acl:` for a Windows ACL change).
- Keep the description short, starting lowercase, with no trailing period — match the existing log (`core: deny rules`, `windows: fix deny behaviour`, `*.toml: tombi fmt`).

**Edge cases:**

- **Several areas touched** — comma-separate the scopes (`linux, macos:`) or pick the broader scope that covers them. Don't drop the scope.
- **Whole-tree / cross-cutting change** (formatting, deps, repo-wide docs or CI) — use `treewide`, or a file-pattern scope the repo already uses (`*.toml:`).
- **No single scope fits** — the commit is probably too broad; consider splitting it (jj makes this cheap with `jj split`).
- **Ticket reference** — put it in parentheses after the scope (`core (PROJ-123): ...`) or as a trailer in the body.
- **Breaking change** — scoped commits defines no `!` / `BREAKING CHANGE:` marker; call it out in the body instead.
- **Reverts and merges** — may take any form; the scope-first rule is for ordinary commits only.

This repo is jj, not git — set the message on the current change with `jj describe -m "scope: description"`.

## Commands

- In `crates/guardrail-napi`, use pnpm as the package manager, not npm.
- CI currently builds the napi binary for all six targets and runs `pnpm test` on the host targets.
- The default Rust test set is `cargo test --all-targets`, which covers `guardrail-core`, the `guardrail` facade, `guardrail-napi`, and the native backend selected by target-specific dependencies. Test a platform backend directly only on its native host with `cargo test -p guardrail-<os> --all-targets`.

## Architecture

**`guardrail-core` (platform-agnostic).** Defines all the public types and the contract backends implement.

**`guardrail` (facade).** Re-exports `guardrail-core` and exposes `PlatformBackend`, selected at build time with target-specific dependencies. Rust users should depend on this crate unless they intentionally need a backend crate directly.

**Platform backends.** Each implements `Backend` and applies confinement. Linux and macOS do all confinement inside `std::process::Command::pre_exec` (after fork, before exec); Windows launches the child suspended, installs policy (Job Object + AppContainer + ACL), then resumes.

- `guardrail-linux` — Landlock (fs), seccomp-BPF (network + IPC), `setrlimit` (resources), `NO_NEW_PRIVS` first. Seccomp is applied **last** so its filter doesn't interfere with Landlock's setup syscalls. The only backend that consumes `SandboxConfig::linux_ipc`.
- `guardrail-macos` — Seatbelt (`painless-belt`) + `setrlimit`. Profile generation is pure Rust, but the crate is native-only and tested on macOS. Seatbelt uses `(deny default)`, so a real binary often needs runtime grants (dyld paths, sysctl names) beyond the portable policy; the `darwin_sandbox_profiles` escape hatch + the crate-level tips doc are the answer — see `guardrail-macos/src/lib.rs`. `linux_ipc` is ignored: IPC follows the generated and imported Seatbelt rules, and network grants can permit Unix-domain socket connections.
- `guardrail-windows` — AppContainer (per-run SID, fs/network), Job Object (process tree dies with the sandbox), ACL grants are *additive* (only ever append ACEs). `linux_ipc` is ignored; AppContainer baseline isolation applies independently (see the crate docs for its access checks and limits).

**`guardrail-napi` (Node bindings).** One `spawn(command, args?, options?)` function; `options` mirrors `SandboxConfig` fields (camelCase, see `SpawnOptions`). The backend comes from the Rust `guardrail::PlatformBackend` facade — each published binary targets exactly one OS. `wait()` runs on the libuv threadpool via `WaitTask`. `stdio` is inherited; output capture is not yet supported.

## Testing conventions

- Every platform crate ships a `guardrail-<os>-probe` binary (`src/bin/`), a deterministic helper that exits `0` (allowed), `3` (denied — the expected sandboxed result), or `2` (usage error). Integration tests in `crates/guardrail-*/tests/` spawn the probe under a policy and assert the exit code. Locate the probe via the `CARGO_BIN_EXE_guardrail-<os>-probe` env var Cargo sets for tests — reuse this pattern when adding integration tests rather than depending on arbitrary system binaries.
- Platform-backend crates are native-only. Do not add non-target `Error::Unsupported` backend implementations just to make a foreign host compile them; normal consumers should reach the selected backend through `guardrail::PlatformBackend`.
