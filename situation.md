# Guardrail Windows backend — work-in-progress situation

_Last updated: 2026-07-24 (second update: dev-tool matrix fully green)._

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

## 4. RESOLVED: the "msys getcwd" mystery (was the top blocker)

The old hypothesis (LPAC blocks msys ancestor stats) was **wrong** on both
counts, proven by experiment:

- Classic AppContainer (omitting the `ALL_APPLICATION_PACKAGES_POLICY`
  attribute entirely — passing the attribute with value `0` fails CreateProcess
  with `ERROR_ENVVAR_NOT_FOUND`!) was verified active via the LPAC
  discriminator test — and git/jj failed **identically**. LPAC was never the
  cause; the LPAC opt-out idea is dead and LPAC stays unconditional.
- git.exe (mingw, not msys-linked) and jj (pure Rust) fail on
  `GetFinalPathNameByHandleW(VOLUME_NAME_DOS)` = `std::fs::canonicalize`, and
  on ancestor stats during repo discovery — not on msys path emulation.

Three independent root causes were found and fixed:

1. **`\Device\MountPointManager`** — DOS/GUID final-name resolution queries
   this device; its DACL (`FX` to Everyone and `RESTRICTED`, no package SID)
   fails the AppContainer gate. Probe experiments confirmed `NtOpenFile(FX)` +
   `IOCTL_MOUNTMGR_QUERY_DOS_VOLUME_PATH` work once granted; there is **no
   driver-level sandbox check**. Fixed by extending the elevated helper: grant
   `FX|RA|RC|SYNCHRONIZE` (`MOUNTMGR_MASK`) to S-1-15-2-2 + S-1-15-2-1 —
   implicit-bits lesson again: `CreateFileW`-style opens silently add
   `SYNCHRONIZE`/`FILE_READ_ATTRIBUTES`, and each sandbox gate accumulates only
   from its own ACEs. Wired as
   `configure_mount_point_manager_access`/`mount_point_manager_access_configured`
   in `nul.rs`, applied+checked by `guardrail-nul-setup` alongside the NUL
   grant. Resets on reboot (device object), like NUL.
2. **Ancestor traverse/stat** — git's repo discovery and cmd's `dir`/`del`
   stat every ancestor of the cwd up to the root. User-profile ancestors carry
   no package ACEs under either AC flavor. Fixed with **non-inheritable**
   `(X,RA,S,RC)` grants to `S-1-15-2-2` on each ancestor: unprivileged icacls
   works for the user-owned chain (`C:\Users\EFL` and below); `C:\` and
   `C:\Users` needed one elevated icacls each. NTFS ACEs **persist across
   reboots** (unlike the device grants). Not yet productized — see next steps.
3. **Env hygiene** — napi spawns clear the environment; AppContainer
   `CreateProcessAsUserW` needs `SystemRoot`/`LOCALAPPDATA`/`USERPROFILE` or it
   fails with error 203 (`ERROR_ENVVAR_NOT_FOUND`). For git/jj set `HOME` (jj
   reads `~/.gitconfig`) and optionally `GIT_CEILING_DIRECTORIES`.

### Current live tool matrix (LPAC, all grants present, verified 2026-07-24)

| Tool | Result |
|---|---|
| `cmd` findstr / `>nul` / `dir` / write&&ren&&del one-liner | PASS |
| `git` version / init / status (mingw git.exe) | PASS |
| `jj` version / `jj git init` | PASS |
| `go` version / build | PASS |
| true msys binaries (`sh.exe`, `pwd.exe`, `ls.exe` from git `usr\bin`) | FAIL `0xC0000142` (msys-2.0.dll runtime init; separate deep AppContainer incompatibility — document as limitation; affects git shell hooks only) |
| `curl`/TLS | untested since cert-store finding (needs `%APPDATA%\Microsoft\SystemCertificates` read grant) |

Probe additions used for the bisection (kept): `cwd-report` (current_dir /
canonicalize / read_dir / GetFinalPathNameByHandleW flavors / mountmgr
NtOpenFile+IOCTL) and `open-bits <path> <hex>`.

---

## 5. Decisions taken (via AskUserQuestion / discussion)

- Diff-state store: **guardrail-managed manifest** with an optional override
  path.
- Startup verification: **configurable** (none | deny roots | all roots).
- Unrestricted-FS mode: **out of scope**, document it.
- LPAC: **stays unconditional.** The opt-out investigation concluded: classic
  AC (attribute omitted — note passing the attribute with value `0` fails
  CreateProcess with error 203) changed nothing for the failing tools, and the
  full dev-tool matrix is green under LPAC. The classic-AC-option idea is moot
  unless a new AAP-only blocker appears.
- Ancestor grants: initially dropped, but turned out to be the only fix for
  ancestor stats (git discovery, cmd dir/del) — revived as sticky
  non-inheritable `S-1-15-2-2` grants (§4.2). **How to productize is an open
  question for the user.**
- NUL persistence: **boot scheduled task** (registered by `guardrail-nul-setup`),
  not a Windows service. The mountmgr grant rides the same task; the NTFS
  ancestor grants don't need it (persistent).

---

## 6. NEXT STEPS (in priority order)

### A. Productize the ancestor + device grants — DONE (2026-07-24)
- `nul.rs` renamed to `host.rs`; bin renamed `guardrail-host-setup` (applies
  and checks NUL + mountmgr device grants and the system ancestor traverse
  grants: fixed-drive roots + user-profile parent).
- `AclGuard::apply` stamps sticky non-inheritable `TRAVERSE_MASK` grants for
  `S-1-15-2-2` on every allow root's ancestors, best-effort (user-owned chain
  succeeds; system roots skipped, covered by the helper). Verified end-to-end:
  git init/status green in a fresh deep chain with no manual icacls.
- Documented in `guardrail-windows` crate docs (host setup + known
  limitations) and the napi README Windows Setup Guide (task #4 DONE).

### B. Device-grant boot scheduled task + revert path — DONE (2026-07-24)
- `guardrail-host-setup` gained `--register` (applies grants + registers a
  SYSTEM ONSTART schtasks task), `--unregister`, and `--revert`
  (mask-subtracting revert that restores pre-existing ACEs bit-for-bit).
- napi: `windowsHostSetupConfigured()` and
  `cleanupWindowsNamespace(namespace?, manifestDir?)` exported; facade
  re-exports the underlying fns on Windows.

### C. Persistent ACL cache + canonical-set diff (task #3) — DONE (2026-07-24)
- `guardrail-core`: new `SandboxConfig::windows_manifest_dir` +
  `windows_acl_verification` (`WindowsAclVerification`: None | DenyRoots
  [default] | AllRoots).
- `appcontainer.rs`: profile name and restricting SIDs (4/5 sub-authority,
  FNV-1a-derived) are deterministic per namespace; profiles are no longer
  deleted on drop.
- `manifest.rs` (new): per-namespace dir (default
  `%LOCALAPPDATA%\guardrail\<ns>-<hash>`), line-format manifest of applied
  canonical rules (write-then-rename), `ActiveMarker` (open handle without
  FILE_SHARE_DELETE; delete-probe detects liveness) rejecting a *different*
  policy while active elsewhere, admitting an identical one.
- `acl.rs`: ACE application rebuilt around a canonical `Op` set
  (path × principal × allow/deny × mask). Unchanged policy → verify per
  config (mismatch → full rebuild self-heal); changed policy → set-diff with
  a consistency gate (touched roots must match the manifest's expected ACEs,
  else rebuild); no manifest → fresh apply. Nothing is stripped on drop.
- `cache.rs`: orchestrates manifest+marker+profile; `cleanup_namespace`
  (exported, also via facade+napi) strips recorded ACEs, deletes the profile
  and manifest dir; refuses while active.
- Verified: unit+integration suites green (42 unit, 31 policy incl. new
  reuse/diff/self-heal/persist-after-drop tests); live two-process run:
  first build 5.6s (full propagation), second process 42ms (verify-only),
  enforcement identical, cleanup clean.

### D. napi README (task #4) — DONE, extended with Persistent ACL Cache
  section, host-setup --register guide, and the new option/function docs.

---

## 7. How to verify / useful commands

- Full backend suite: `cargo test -p guardrail-windows --all-targets`
  (native-only; ~90s; one ignored network test needs host AppContainer loopback,
  one ignored process-count test). Verified green after all §4 changes.
- Setup helper: build `cargo build -p guardrail-windows --bin guardrail-nul-setup`;
  check `target/debug/guardrail-nul-setup.exe --check` (reports NUL + mountmgr);
  apply (elevated) `guardrail-nul-setup.exe`. **Both device grants are
  currently PRESENT on this dev machine; they reset on reboot.** The NTFS
  ancestor grants (`C:\`, `C:\Users` elevated; `C:\Users\EFL` chain
  unprivileged; all `(X,RA,S,RC)` → `*S-1-15-2-2`, non-inheritable) are
  applied and persist.
- napi debug binding: `cd crates/guardrail-napi && pnpm build:debug`
  (use pnpm, not npm). Smoke test: `pnpm test`.
- Live tool probing was done via throwaway `.mjs` scripts driving
  `Sandbox.build({...}).spawn(...)`; all such scratch files have been cleaned
  up. Spawn env must include `SystemRoot`/`LOCALAPPDATA`/`USERPROFILE` (else
  CreateProcess error 203) plus tool-specific vars (`GOROOT`/`GOCACHE`,
  `HOME`, PATH incl. the tool's own bin dir).
- Tool locations on this machine (scoop): git
  `D:\scoop\apps\git\2.55.0.3\mingw64\bin\git.exe`, jj
  `D:\scoop\apps\jj\current\jj.exe`, go `D:\scoop\apps\go\1.26.5`, rust sysroot
  `D:\scoop\persist\rustup\.rustup\toolchains\stable-x86_64-pc-windows-msvc`,
  pnpm real exe under `%LOCALAPPDATA%\pnpm\global\v11\...\@pnpm\exe\pnpm.exe`.
- **Do not put scratch allow rules on `D:\scoop` (or other big shared trees)**:
  sandbox build/teardown propagates + strips inheritable ACEs across the whole
  tree and transiently broke the user's running apps once. Grant per-tool
  version dirs instead.

---

## 8. Files touched (uncommitted working copy at time of writing)

- `M acl.rs` — delete in write masks, `FILE_READ_ATTRIBUTES`, nested re-allow
  (`shadowed_by_deny`, reallow SID), removed `reject_nested_reallow`.
- `M appcontainer.rs` — `reallow_sid`, `random_restricting(count)`, registryRead
  for Deny, lpacCryptoServices/lpacIdentityServices, capability-count tests.
- `M cache.rs` — thread `reallow_sid` into `AclGuard::apply`.
- `M process.rs` — pass `reallow_sid` to `restricted_token`; extra restricting
  SID. LPAC restored unconditional after the classic-AC experiment.
- `M lib.rs` — corrected docs (re-allow, write=delete), export `nul` fns
  (now four: NUL + mountmgr configure/check), `mod nul`.
- `M tests/policy.rs` — new re-allow / delete / rename / overwrite / NUL tests.
- `A nul.rs` — device grants, generalized: NUL (read/write) + mount-point
  manager (`MOUNTMGR_MASK`).
- `A bin/guardrail-nul-setup.rs` — elevated helper, applies/checks both grants.
- `M bin/guardrail-windows-probe.rs` — write-nul/read-nul/overwrite/delete/
  rename plus diagnostics `cwd-report` and `open-bits`.

Memory files (agent long-term memory, not in repo):
`feedback-last-rule-wins-never-reject.md`, `windows-acl-rework-direction.md`
(both updated with the above findings + decisions).
