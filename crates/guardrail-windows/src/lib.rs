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
//! Two limits of that boundary:
//!
//! * The child is a regular AppContainer, not an LPAC. Some system files,
//!   registry keys, and COM/RPC endpoints deliberately grant regular
//!   AppContainers access, often through `ALL APPLICATION PACKAGES`. Such a
//!   grant only satisfies the AppContainer side of the dual-principal check;
//!   the user's normal SIDs, integrity level, and other policy still apply.
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
