//! Windows backend for `guardrail`.
//!
//! On Windows this crate launches children suspended, assigns them to a Job
//! Object, places them in a cached AppContainer for filesystem/network
//! confinement, and resumes them only after all policy is installed.
//!
//! # IPC
//!
//! The Linux-only `linux_ipc` policy is ignored here; Windows has no
//! configurable IPC knob. AppContainer baseline isolation applies
//! independently:
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
//!   adds a private restricting SID to the child's conventional restricted-token
//!   check. Filesystem allow rules grant the package SID, while deny rules deny
//!   the restricting SID. Both checks must pass, so the conventional deny vetoes
//!   package and capability grants. Inheritable ACEs cover existing and future
//!   descendants of an existing policy root that participate in inheritance.
//! * A deny directory is rejected if its existing tree contains a reparse
//!   point, null DACL, or protected descendant DACL. This keeps inheritance
//!   fail-closed without traversing a junction target or snapshotting host
//!   security descriptors.
//! * ACLs attach to the existing policy root object. If trusted host code
//!   deletes and recreates that root while the sandbox is active, the new
//!   object is not protected by the old root's ACEs.
//! * Windows ACL inheritance cannot re-allow a child beneath an inherited deny
//!   for the same right. Such a policy is rejected during backend construction.
//! * Children sharing a cached profile (same host process,
//!   `windows_cache_namespace`, and filesystem policy) share one package SID
//!   and profile directory, so they are not isolated from each other.

#![cfg(windows)]

mod acl;
mod appcontainer;
mod backend;
mod cache;
mod handle;
mod job;
mod process;

pub use backend::WindowsBackend;
