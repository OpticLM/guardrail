//! Windows backend for `guardrail`.
//!
//! On Windows this crate launches children suspended, assigns them to a Job
//! Object, places them in a cached AppContainer for filesystem/network
//! confinement, and resumes them only after all policy is installed. The core
//! `IpcPolicy` is currently a documented no-op on Windows; there is no Windows
//! IPC restriction layer yet.

use std::process::Command;
#[cfg(windows)]
use std::sync::Arc;

use guardrail_core::{Backend, Error, SandboxChild, SandboxConfig};

#[cfg(windows)]
mod acl;
#[cfg(windows)]
mod appcontainer;
#[cfg(windows)]
mod cache;
#[cfg(windows)]
pub mod diagnostics;
#[cfg(windows)]
mod handle;
#[cfg(windows)]
mod job;
#[cfg(windows)]
mod process;

/// The Windows sandbox backend.
pub struct WindowsBackend {
    config: SandboxConfig,
    #[cfg(windows)]
    appcontainer: Arc<cache::CachedAppContainer>,
}

impl WindowsBackend {
    /// Create a new Windows backend.
    pub fn new(config: SandboxConfig) -> Result<Self, Error> {
        #[cfg(windows)]
        {
            let appcontainer = cache::get(&config)?;
            Ok(Self {
                config,
                appcontainer,
            })
        }

        #[cfg(not(windows))]
        {
            Ok(Self { config })
        }
    }
}

impl Backend for WindowsBackend {
    #[cfg(windows)]
    fn spawn(&self, mut command: Command) -> Result<SandboxChild, Error> {
        command.env_clear();
        command.envs(&self.config.env);

        let job = job::create(&self.config)?;
        process::launch(
            command,
            job,
            Arc::clone(&self.appcontainer),
            self.config.network,
        )
    }

    #[cfg(not(windows))]
    fn spawn(&self, _command: Command) -> Result<SandboxChild, Error> {
        Err(Error::Unsupported(
            "guardrail-windows is only available on Windows".into(),
        ))
    }

    #[cfg(windows)]
    fn explain(&self, ctx: &guardrail_core::ExplainCtx<'_>) -> Option<guardrail_core::Violation> {
        diagnostics::explain(ctx)
    }
}
