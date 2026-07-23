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
//! * Children sharing a cached profile (same host process,
//!   `windows_cache_namespace`, and filesystem policy) share one package SID
//!   and profile directory, so they are not isolated from each other.
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
mod job;
mod nul;
mod process;

pub use backend::WindowsBackend;
pub use nul::{configure_null_device_write, null_device_write_configured};
