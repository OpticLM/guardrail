//! Windows backend for `guardrail`.
//!
//! On Windows this crate launches children suspended, assigns them to a Job
//! Object, places them in a cached AppContainer for filesystem/network
//! confinement, and resumes them only after all policy is installed. The core
//! `IpcPolicy` is currently a documented no-op on Windows; there is no Windows
//! IPC restriction layer yet.

#[cfg(windows)]
mod acl;
#[cfg(windows)]
mod appcontainer;
#[cfg(windows)]
mod backend;
#[cfg(windows)]
mod cache;
#[cfg(windows)]
mod handle;
#[cfg(windows)]
mod job;
#[cfg(windows)]
mod process;

#[cfg(windows)]
pub use backend::WindowsBackend;
