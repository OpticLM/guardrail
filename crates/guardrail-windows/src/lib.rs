//! Windows backend for `guardrail`.
//!
//! On Windows this crate launches children suspended, assigns them to a Job
//! Object, places them in a per-run AppContainer for filesystem/network
//! confinement, and resumes them only after all policy is installed. The core
//! `IpcPolicy` is currently a documented no-op on Windows; there is no Windows
//! IPC restriction layer yet.

use std::process::Command;

use guardrail_core::{Backend, Error, SandboxChild, SandboxConfig};

#[cfg(windows)]
mod acl;
#[cfg(windows)]
mod appcontainer;
pub mod diagnostics;
#[cfg(windows)]
mod handle;
#[cfg(windows)]
mod job;
#[cfg(windows)]
mod process;

/// The Windows sandbox backend.
#[derive(Debug, Default, Clone)]
pub struct WindowsBackend {
    _private: (),
}

impl WindowsBackend {
    /// Create a new Windows backend.
    pub fn new() -> Self {
        Self::default()
    }
}

impl Backend for WindowsBackend {
    #[cfg(windows)]
    fn spawn(&self, config: &SandboxConfig, command: Command) -> Result<SandboxChild, Error> {
        let appcontainer = appcontainer::AppContainerProfile::create(config.network)?;
        let acl = acl::AclGuard::apply(&config.fs, appcontainer.sid())?;
        let job = job::create(config)?;
        process::launch(command, job, appcontainer, acl)
    }

    #[cfg(not(windows))]
    fn spawn(&self, _config: &SandboxConfig, _command: Command) -> Result<SandboxChild, Error> {
        Err(Error::Unsupported(
            "guardrail-windows is only available on Windows".into(),
        ))
    }
}
