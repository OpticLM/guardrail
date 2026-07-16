#![cfg(windows)]

use std::process::Command;
use std::sync::Arc;

use guardrail_core::{Backend, Result, SandboxChild, SandboxConfig};

use crate::{cache, job, process};

/// The Windows sandbox backend.
pub struct WindowsBackend {
    config: SandboxConfig,
    appcontainer: Arc<cache::CachedAppContainer>,
}

impl WindowsBackend {
    /// Create a new Windows backend.
    pub fn new(config: SandboxConfig) -> Result<Self> {
        let appcontainer = cache::get(&config)?;
        Ok(Self {
            config,
            appcontainer,
        })
    }
}

impl Backend for WindowsBackend {
    /// AppContainer and Job Objects exist on every Windows version this crate
    /// compiles for (std itself requires Windows 10+), so support is
    /// unconditional.
    fn probe_support() -> Result<()> {
        Ok(())
    }

    fn spawn(&self, mut command: Command) -> Result<SandboxChild> {
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
}
