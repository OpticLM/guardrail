//! Windows backend for `guardrail`.
//!
//! On Windows this crate launches children suspended, assigns them to a Job
//! Object, and resumes them only after resource limits are installed. The
//! AppContainer filesystem/network policy layer is added separately.

use std::process::Command;

use guardrail_core::{Backend, Error, SandboxChild, SandboxConfig};

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
        let job = job::create(config)?;
        process::launch(command, job)
    }

    #[cfg(not(windows))]
    fn spawn(&self, _config: &SandboxConfig, _command: Command) -> Result<SandboxChild, Error> {
        Err(Error::Unsupported(
            "guardrail-windows is only available on Windows".into(),
        ))
    }
}
