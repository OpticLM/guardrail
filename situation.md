# Guardrail Windows backend — work-in-progress situation

_Last updated: 2026-07-24._

This document captures the full state of an in-flight effort to improve the
`guardrail-windows` backend, so the task can be handed off or the conversation
compacted without losing context. Read it top to bottom before continuing.

---

## 1. Original goals (from the user)

The user is building/refining the Windows process-sandbox backend. Four threads
were opened, in order:

1. **Filesystem semantics correctness.** The Windows backend was rejecting
   valid ordered rule lists and missing delete semantics. The user was
   emphatic (now a saved memory) that:
   - Ordered `FsAccess` rules must follow **last-rule-wins** and must **never be
     rejected** at construction. The SDK embeds end-user rules after a host
     app's defaults; users assume "last rule wins, nothing bad happens." A
     construction-time error from a valid combination breaks that model. Only
     path canonicalization-style processing is acceptable; do not "compile"
     rules into an error.
   - **Nested re-allow** (allow a child beneath a denied ancestor) is a
     legitimate, required shape. Linux already supports it; Windows rejecting it
     was an outlier bug.
   - Windows **write semantics must include delete/rename**. Missing the
     `DELETE` bit was a bug.

2. **Persistent, cross-process ACL cache with diffing** (NOT YET STARTED — task
   #3). Today's cache is process-local and evaporates on drop, re-propagating
   inheritable ACEs over the whole tree every run. The agreed direction:
   - Stable AppContainer profile name + deterministic restricting SIDs derived
     from the namespace (drop the pid+random nonce).
   - A guardrail-managed **per-namespace manifest** (default under
     `%LOCALAPPDATA%\guardrail\<namespace>`, with a config option to override
     the path) storing the previously-applied canonical rules + applied roots,
     with an advisory lock for cross-process different-policy detection.
   - Do **not** strip ACEs on drop; ship an explicit cleanup helper the app
     calls when retiring a namespace.
   - Policy changes apply as a **set-diff of compiled canonical ACE-sets** (per
     root), not a full rebuild: removed rule → remove that root's ACE and let
     inheritance restore the surrounding effect; added rule → add ACE.
     Self-heal: if on-disk state at a touched root doesn't match the expected
     old canonical state, rebuild the namespace from scratch.
   - Startup verification is **configurable**: none | deny roots | all rule
     roots (default recommended: deny roots).
   - "Unrestricted filesystem" mode is **out of scope** — document that
     AppContainer inherently default-denies the filesystem.

3. **NUL-device write grant** (mechanism DONE + proven; plumbing NOT done —
   task #5). See section 4.

4. **napi README Windows setup guide** (BLOCKED on tool verification — task #4).
   The user wants a Windows dev-tools baseline + per-tool setup guide "just like
   those for other platforms" (Linux/macOS sections already exist in
   `crates/guardrail-napi/README.md`, each with real "Tested result:" lines).

---

## 2. Architecture recap (how Windows FS confinement works)

A guardrail child is launched suspended, assigned to a Job Object, placed in an
AppContainer (currently **LPAC** — Less-Privileged), and given a **restricted
token** (Chromium `USER_RESTRICTED_SAME_ACCESS`-style). Policy is installed,
then the child is resumed.

**Critical model: every access check passes THREE gates, all must grant:**
1. Normal enabled SIDs vs the object DACL.
2. The token's **restricting SIDs** vs the DACL (user SID, non-integrity token
   groups incl. Authenticated Users, guardrail's private filesystem SID and
   re-allow SID).
3. The **AppContainer** package/capability check. Under LPAC only
   `ALL RESTRICTED APPLICATION PACKAGES` (S-1-15-2-2) is honored; a classic
   AppContainer also honors `ALL APPLICATION PACKAGES` (S-1-15-2-1).

Guardrail `fs` allow rules append an **inheritable grant ACE for the package
SID**; deny rules append an inheritable **deny ACE for the filesystem
restricting SID** (AppContainer checks ignore deny ACEs, so the conventional
restricted-token check enforces denies). NTFS inheritance covers existing and
future descendants. Because an allow **mutates the target's DACL** (needs
`WRITE_DAC`, propagates to the whole subtree), you can only grant paths you own
— **system dirs cannot be listed in `fs`** but are already reachable by
AppContainers via built-in `ALL [RESTRICTED] APPLICATION PACKAGES` ACEs. This is
structurally different from Linux/macOS `/usr` grants.

Files: `crates/guardrail-windows/src/{acl,appcontainer,cache,process,backend,nul,handle,job,lib}.rs`.

---

## 3. DONE and verified (full `guardrail-windows` suite green: 36 unit + 28 policy integration, others)

### 3a. Write includes delete/rename (`acl.rs`)
- `allow_mask(Write)` = `FILE_GENERIC_WRITE | DELETE | FILE_READ_ATTRIBUTES`.
  - `DELETE` makes write grants cover deletion and rename. **Never**
    `FILE_DELETE_CHILD` (it would let the child delete inside write-denied
    subdirs via the parent).
  - `FILE_READ_ATTRIBUTES` is required because kernel32 opens (CreateFileW,
    MoveFileExW) implicitly request it — without it a write grant can't even
    open an existing file. (This was the first live symptom: rename/overwrite
    failed with access-denied until this bit was added.)
- `deny_mask(Write)` also denies `DELETE`.
- New probe commands: `write-nul`, `read-nul`, `overwrite-file`, `delete-file`,
  `rename-file`. New integration tests: delete, rename, overwrite, and
  write-deny-blocks-delete.

### 3b. Nested re-allow (`acl.rs`, `appcontainer.rs`, `process.rs`, `cache.rs`)
- Removed `reject_nested_reallow`. Corrected the false `lib.rs` claim that
  "Windows ACL inheritance cannot re-allow."
- Mechanism: a **third guardrail SID** (`reallow_sid`, 5 sub-authorities vs the
  filesystem SID's 4) in the restricted-token restricting-SID list. For each
  allow root beneath a same-right deny ancestor, emit an explicit grant ACE of
  `deny_mask(right)` for the re-allow SID. Explicit ACEs precede inherited ACEs
  in canonical DACL order, so the grant is consumed before the ancestor's
  inherited deny fires.
- `AppContainerProfile::create` now mints `restricting_sid` (4 sub-auth) and
  `reallow_sid` (5 sub-auth) via `Sid::random_restricting(count)`.
- Tested with the user's alternating-rules example and
  re-allowed-directory-covers-future-files.

### 3c. Capability fixes (`appcontainer.rs`) — found empirically
- `registryRead` is now granted at **every** network level including `Deny`.
  Without it Winsock `WSAStartup` fails, which breaks Go, libcurl, and msys
  tools at startup **even for pure file work**.
- `lpacCryptoServices` + `lpacIdentityServices` added for `OutboundOnly`/`Full`
  so schannel TLS can enumerate security packages (mirrors Chromium's network
  sandbox). Capability-count unit tests updated (Deny=1, OutboundOnly=4,
  Full=5).

### 3d. NUL-device write grant — MECHANISM DONE + PROVEN (`nul.rs`, `bin/guardrail-nul-setup.rs`)
The dominant blocker for real dev tools. A child under LPAC+restricted-token
cannot even **read** `\Device\Null`, because its default DACL grants **no
app-package SID** (fails gate 3), and its only write grant is to `Everyone`
(S-1-1-0), which isn't a restricting SID (fails gate 2 for writes). This broke
`git` (`could not open /dev/null`), `go` (`open NUL: Access is denied`), and
`cmd >nul`.

Fix (applied by an **elevated** helper, since it needs `WRITE_DAC` on the device
and the descriptor resets on reboot): grant on `\Device\Null`:
- `ALL RESTRICTED APPLICATION PACKAGES` (S-1-15-2-2) + `ALL APPLICATION
  PACKAGES` (S-1-15-2-1): `FILE_GENERIC_READ | FILE_GENERIC_WRITE` (gate 3).
- `Authenticated Users` (S-1-5-11, already a restricting SID): `FILE_GENERIC_WRITE`
  (gate 2 for the write path; read is covered by the default DACL).

**Critical detail:** masks MUST be full generic sets. `GENERIC_READ/WRITE` opens
implicitly request `SYNCHRONIZE` + `READ_CONTROL`, and each gate accumulates
access ONLY from ACEs matching that gate's SIDs, so partial (data/EA/attr-only)
app-package grants are denied. This took three elevated iterations to pin down.

- Public API: `guardrail_windows::{configure_null_device_write,
  null_device_write_configured}` (both `io::Result`).
- Bin `guardrail-nul-setup`: no args = configure (needs elevation); `--check` =
  report present(0)/absent(3), unprivileged.
- Gated integration test `sandboxed_process_can_write_nul_when_host_configured`
  skips when the grant is absent, else spawns a sandboxed child that writes NUL
  and asserts success. **Verified green on this machine** after the user ran the
  helper elevated.

**PROVEN EFFECT:** after the grant, `go build` and `cmd …>nul` now PASS in the
sandbox where they were fully blocked before.

---

## 4. Current blockers / open findings (live dev-tool verification)

Testing real tools via a rebuilt napi debug binding
(`crates/guardrail-napi`, `pnpm build:debug`) with a workspace-only `fs` policy:

| Tool | Result | Cause |
|---|---|---|
| `cmd` findstr, `>nul` | PASS | — |
| `go build` | PASS | (was NUL-blocked) |
| `cmd` write / rename (standalone) | PASS | — |
| `cmd` write&&rename&&del one-liner | FAIL | Unisolated cmd/inheritance quirk; standalone delete passes in the integration suite. |
| `git` (git-for-windows / msys) | FAIL | `unable to get current working directory: Permission denied`. msys POSIX `getcwd` stats the ancestor path chain; LPAC gate blocks ancestor dirs that only grant `Everyone`/`ALL APPLICATION PACKAGES`. Not fixed by workspace location (also fails under `C:\Users\Public`). |
| `jj` | FAIL | Same "Could not determine current directory" — same msys/ancestor-access class. |
| `curl`/TLS | FAIL | schannel needs the user cert store read-allowed (`%APPDATA%\Microsoft\SystemCertificates`); crypto capabilities alone insufficient. |

Key insight: **msys-based tools fail under LPAC** due to ancestor-path access
during `getcwd`; **native-Windows tools (go) work**. System dirs can't be
granted (ACL mutation fails on protected subtrees) but are already reachable.

---

## 5. Decisions taken (via AskUserQuestion)

- Diff-state store: **guardrail-managed manifest** with an optional override
  path.
- Startup verification: **configurable** (none | deny roots | all roots).
- Unrestricted-FS mode: **out of scope**, document it.
- LPAC: originally "keep unconditional"; **now superseded** — user chose
  **"Investigate LPAC opt-out"** so git/jj can work (see next steps).
- NUL persistence: **boot scheduled task** (registered by `guardrail-nul-setup`),
  not a Windows service.

---

## 6. NEXT STEPS (in priority order)

### A. Investigate LPAC opt-out (IN PROGRESS — highest leverage for the README)
- Hypothesis: opting out of LPAC (regular AppContainer that honors
  `ALL APPLICATION PACKAGES`) lets msys `getcwd` traverse ancestor dirs
  (`C:\`, `C:\Users`, …) that grant `ALL APPLICATION PACKAGES`, unblocking
  git/jj. An earlier `all_application_packages_policy = 0` experiment failed,
  but that was BEFORE the NUL + registryRead fixes — must re-test now.
- The exact spot: `crates/guardrail-windows/src/process.rs` ~line 108:
  ```rust
  let mut all_application_packages_policy =
      Box::new(PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT);
  ```
  Set to `0` (opt-in / regular AppContainer) to test. Applied via
  `PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY`.
- Plan: (1) temporarily hardcode `0`, rebuild napi debug, re-test git/jj/go/cmd.
  (2) If it unblocks msys tools, wire it as a real config option through
  `guardrail-core::SandboxConfig` → facade → `guardrail-napi` `SpawnOptions`
  (LPAC on by default, opt-out flag). Note LPAC widens ambient reach to
  `ALL APPLICATION PACKAGES`-granting objects — document the trade-off. Keep the
  `lpac_removes_all_packages_but_keeps_package_and_capability_allows` test
  meaningful (gate it on the LPAC setting).

### B. NUL boot scheduled task + revert path
- Extend `guardrail-nul-setup` (or a sibling) with `--register` (create a
  SYSTEM boot task via Task Scheduler / `schtasks` or the COM API that runs the
  configure step), `--unregister`, and `--revert` (remove the added ACEs from
  `\Device\Null`). Provide a napi helper `nullDeviceWriteConfigured()` and
  document that skipping registration degrades any tool writing to NUL.

### C. Persistent ACL cache + canonical-set diff (task #3, not started)
- See section 1.2 for the full agreed design.

### D. napi README Windows section (task #4)
- Blocked on A + the tool matrix. Write it modeled on the Linux/macOS sections:
  correct Windows baseline (do NOT list system dirs; only owned paths),
  Windows-specific semantics (ACL-mutating allows, write=delete, nested
  re-allow, per-namespace package SID), real caveats (NUL setup requirement,
  cert store for TLS, LPAC vs msys tools), and per-tool recipes with **honest**
  "Tested result" lines — only claim what's actually been verified green.
  `go` works today; git/jj pending the LPAC investigation.

---

## 7. How to verify / useful commands

- Full backend suite: `cargo test -p guardrail-windows --all-targets`
  (native-only; ~90s; one ignored network test needs host AppContainer loopback,
  one ignored process-count test).
- NUL helper: build `cargo build -p guardrail-windows --bin guardrail-nul-setup`;
  check `target/debug/guardrail-nul-setup.exe --check`; apply (elevated)
  `guardrail-nul-setup.exe`. **The grant is currently PRESENT on this dev
  machine** (applied during verification; resets on reboot).
- napi debug binding: `cd crates/guardrail-napi && pnpm build:debug`
  (use pnpm, not npm). Smoke test: `pnpm test`.
- Live tool probing was done via throwaway `.mjs` scripts driving
  `Sandbox.build({...}).spawn(...)`; all such scratch files have been cleaned up.
- Tool locations on this machine (scoop): git
  `D:\scoop\apps\git\2.55.0.3\mingw64\bin\git.exe`, jj
  `D:\scoop\apps\jj\current\jj.exe`, go `D:\scoop\apps\go\1.26.5`, rust sysroot
  `D:\scoop\persist\rustup\.rustup\toolchains\stable-x86_64-pc-windows-msvc`,
  pnpm real exe under `%LOCALAPPDATA%\pnpm\global\v11\...\@pnpm\exe\pnpm.exe`.

---

## 8. Files touched (uncommitted working copy at time of writing)

- `M acl.rs` — delete in write masks, `FILE_READ_ATTRIBUTES`, nested re-allow
  (`shadowed_by_deny`, reallow SID), removed `reject_nested_reallow`.
- `M appcontainer.rs` — `reallow_sid`, `random_restricting(count)`, registryRead
  for Deny, lpacCryptoServices/lpacIdentityServices, capability-count tests.
- `M cache.rs` — thread `reallow_sid` into `AclGuard::apply`.
- `M process.rs` — pass `reallow_sid` to `restricted_token`; extra restricting
  SID; (LPAC opt-out flip pending).
- `M lib.rs` — corrected docs (re-allow, write=delete), export `nul` fns, `mod nul`.
- `M tests/policy.rs` — new re-allow / delete / rename / overwrite / NUL tests.
- `A nul.rs` — null-device grant logic.
- `A bin/guardrail-nul-setup.rs` — elevated helper.
- `M bin/guardrail-windows-probe.rs` — write-nul/read-nul/overwrite/delete/rename.

Memory files (agent long-term memory, not in repo):
`feedback-last-rule-wins-never-reject.md`, `windows-acl-rework-direction.md`
(both updated with the above findings + decisions).
