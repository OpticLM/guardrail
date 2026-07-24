//! Windows backend for `guardrail`.
//!
//! On Windows this crate launches children suspended, assigns them to a Job
//! Object, places them in a cached AppContainer for filesystem/network
//! confinement, and resumes them only after all policy is installed.
//!
//! Standard handles cross the process boundary through an inert, permanently
//! suspended helper process. Guardrail duplicates file, pipe, and device
//! handles into that isolated handle table and declares the helper as the
//! child's parent during creation, so those host copies stay non-inheritable.
//! Windows forbids duplicating console handles for another process, so a child
//! using a real console gets a launch-specific helper that inherits exactly
//! those console handles during its own creation. Every helper belongs to a
//! kill-on-close Job Object and never executes user code. Consequently, system
//! process inspectors report a helper—not the host—as a sandboxed child's
//! immediate parent.
//!
//! # IPC
//!
//! Windows has no configurable IPC knob. AppContainer baseline isolation
//! applies independently:
//!
//! * The child's token pairs the user's SIDs with the profile's package SID
//!   (plus any capability SIDs), and a securable object — named pipe, event,
//!   mutex, section, ALPC port, another process — is only accessible when its
//!   DACL grants access to both the user *and* the package or a capability.
//!   Ordinary objects carry no such grant, so other processes' IPC objects
//!   are unreachable by default. The child also runs at Low integrity level,
//!   which blocks writing to higher-integrity objects and sending window
//!   messages to higher-integrity windows.
//! * Named objects the child creates land in a per-AppContainer object
//!   directory, and its writable profile state lives under the profile's
//!   `AppData\Local\Packages\<profile>\AC` directory.
//!
//! Limits of that boundary:
//!
//! * The child is a Less-Privileged AppContainer (LPAC), so grants to
//!   `ALL APPLICATION PACKAGES` do not satisfy its AppContainer-side access
//!   check. Network-enabled policies add the required `registryRead` and
//!   network capability SIDs; any host object that explicitly grants one of
//!   those capabilities can still be reached when the user side also passes.
//! * AppContainer-side access checks do not honor deny ACEs. Guardrail therefore
//!   adds private restricting SIDs to the child's conventional restricted-token
//!   check. Filesystem allow rules grant the package SID, deny rules deny a
//!   filesystem restricting SID, and an allow beneath a denied ancestor grants
//!   the denied rights back to a separate re-allow SID on that root — explicit
//!   ACEs precede inherited ACEs in the canonical DACL order, so the grant is
//!   consumed before the ancestor's inherited deny is reached. Both checks must
//!   pass, so the conventional deny vetoes package and capability grants.
//!   Inheritable ACEs cover existing and future descendants of an existing
//!   policy root that participate in inheritance.
//! * A deny directory is rejected if its existing tree contains a reparse
//!   point, null DACL, or protected descendant DACL. This keeps inheritance
//!   fail-closed without traversing a junction target or snapshotting host
//!   security descriptors.
//! * ACLs attach to the existing policy root object. If trusted host code
//!   deletes and recreates that root while the sandbox is active, the new
//!   object is not protected by the old root's ACEs.
//! * Write rules include deletion: a write grant carries `DELETE` so the child
//!   can delete and rename within writable trees, and a write deny denies
//!   `DELETE` too. `FILE_DELETE_CHILD` is never granted, so a write-denied
//!   descendant cannot be removed through its parent directory either. Write
//!   grants also carry `FILE_READ_ATTRIBUTES` (file metadata, not content):
//!   kernel32 file opens implicitly request it, so a write grant without it
//!   could not open existing files at all.
//! * Children sharing a cache namespace (`windows_cache_namespace`, same
//!   filesystem policy) share one package SID and profile directory — across
//!   processes, since profiles and restricting SIDs are derived
//!   deterministically from the namespace — so they are not isolated from
//!   each other. A file created under one namespace's policy carries that
//!   namespace's package grants only, so a *different* namespace's children
//!   cannot read it until its own policy root ACEs re-propagate over it.
//! * Policy ACEs, the AppContainer profile, and the per-namespace manifest
//!   (default `%LOCALAPPDATA%\guardrail\<namespace>`, override with
//!   `windows_manifest_dir`) are persistent host state: nothing is removed
//!   when a sandbox drops. The next run verifies an unchanged policy
//!   (`windows_acl_verification`: none / deny roots [default] / all roots,
//!   with a full rebuild as self-heal on mismatch), applies a changed policy
//!   as a set-diff of canonical ACEs, and [`cleanup_namespace`] retires a
//!   namespace explicitly. A namespace active in another process only admits
//!   an identical filesystem policy.
//!
//! # Host setup (`guardrail-host-setup`)
//!
//! Some objects a real workload touches sit outside anything a policy can
//! grant, because their security descriptors are system-owned. The
//! `guardrail-host-setup` binary (also exposed as library functions) applies
//! three grant families; without them the corresponding features degrade as
//! described. `--check` reports their presence unprivileged; applying needs
//! elevation.
//!
//! * **Null device** (`\Device\Null`): its default DACL grants no package SID
//!   and no restricting-SID write, so a sandboxed child cannot even open
//!   `NUL`. Symptoms without the grant: `cmd ... > nul` fails, `go` and `git`
//!   abort on startup. Resets on every boot — re-run the helper per boot (a
//!   scheduled boot task is the intended host).
//! * **Mount-point manager** (`\Device\MountPointManager`):
//!   `GetFinalPathNameByHandleW(VOLUME_NAME_DOS)` — behind
//!   `std::fs::canonicalize` and git's/jj's cwd resolution — queries it, and
//!   its DACL grants no package SID. Symptom without the grant: "could not
//!   determine current directory" from git/jj and `fs::canonicalize`
//!   access-denied everywhere. Resets on every boot.
//! * **System ancestor traverse grants**: sticky, non-inheritable
//!   traverse+stat ACEs (`FILE_EXECUTE | FILE_READ_ATTRIBUTES | READ_CONTROL
//!   | SYNCHRONIZE`, never `FILE_LIST_DIRECTORY`) for
//!   `ALL RESTRICTED APPLICATION PACKAGES` on fixed-drive roots and the
//!   user-profile parent. Tools stat every ancestor of their working
//!   directory (git repo discovery, `cmd`'s `dir`/`del`); user-profile
//!   ancestors carry no package ACEs at all. NTFS ACEs persist across
//!   reboots, so this part is one-time. The backend itself stamps the same
//!   grant best-effort on the *user-owned* ancestors of every allow root at
//!   policy application (unprivileged, idempotent, silently skipping roots it
//!   cannot write), so only the system-owned ancestors need the helper.
//!
//! Trade-off of all three: they widen what *any* AppContainer on the host can
//! reach — NUL read/write, mount-point DOS-name queries, and traverse/stat
//! (not list, not read) of the granted ancestor directories. None of them
//! weakens guardrail's own policy gates.
//!
//! # Known limitations for real workloads
//!
//! * System directories must not appear in `fs` rules: applying a rule
//!   mutates the target's DACL (needs `WRITE_DAC`, propagates inheritable
//!   ACEs over the subtree), which fails on protected system trees — and is
//!   unnecessary, since AppContainers already reach `C:\Windows` etc. through
//!   built-in `ALL [RESTRICTED] APPLICATION PACKAGES` ACEs.
//! * Rule application rewrites DACLs across the whole granted tree the first
//!   time a policy is applied (and when it changes). Granting a large shared
//!   tree (a package store, another application's install root) is slow and
//!   briefly perturbs concurrent access-checks on it; grant the narrowest
//!   directory that works.
//! * The spawn environment starts empty. AppContainer process creation itself
//!   needs `SystemRoot`, `LOCALAPPDATA`, and `USERPROFILE` (missing them
//!   fails with `ERROR_ENVVAR_NOT_FOUND`); tools typically also want `PATH`,
//!   `TEMP`/`TMP`, and a `HOME` pointing somewhere readable.
//! * msys2-runtime binaries (`sh.exe`, msys `pwd.exe`/`ls.exe` — the
//!   `usr\bin` half of Git for Windows) fail to initialize (`0xC0000142`)
//!   under AppContainer. `git.exe` itself (mingw) is unaffected; git features
//!   that shell out to `sh.exe`, such as shell hooks, are not usable.
//! * TLS via schannel needs the user certificate store readable
//!   (`%APPDATA%\Microsoft\SystemCertificates`) in addition to the crypto
//!   capabilities the network policies add.
//!
//! # Program resolution
//!
//! A program given with a path separator is passed to `CreateProcessW` as-is.
//! A bare name is resolved against the `PATH` entry of
//! [`SandboxConfig::env`](guardrail_core::SandboxConfig::env) — the only
//! environment the child sees — following `std::process::Command`'s
//! per-directory rules (`.exe` appended to extensionless names, empty entries
//! skipped). For bare-name resolution, every non-empty entry must be absolute;
//! a relative entry is an `InvalidInput` spawn error because resolving it would
//! consult the host's current-directory state. The host's own `PATH`, its
//! executable directory, the system directories, and the current directory are
//! never searched, so the sandbox configuration alone determines which binary
//! runs; a bare name absent from the configured `PATH` fails to spawn with a
//! `NotFound` error. Spawning a bare name like `cmd` therefore requires putting
//! the expanded system directory, such as `C:\Windows\System32`, in the
//! configured `PATH`.

#![cfg(windows)]

mod acl;
mod appcontainer;
mod backend;
mod cache;
mod handle;
mod host;
mod job;
mod manifest;
mod process;

pub use backend::WindowsBackend;
pub use cache::cleanup_namespace;
pub use host::{
    configure_mount_point_manager_access, configure_null_device_write,
    configure_system_traverse_grants, mount_point_manager_access_configured,
    null_device_write_configured, revert_mount_point_manager_access, revert_null_device_write,
    revert_system_traverse_grants, system_traverse_grants_configured,
};
