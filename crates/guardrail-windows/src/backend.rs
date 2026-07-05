#![cfg(windows)]

use std::process::Command;
use std::sync::Arc;

use guardrail_core::{Backend, Error, SandboxChild, SandboxConfig};

use crate::{cache, diagnostics, job, process};

/// The Windows sandbox backend.
pub struct WindowsBackend {
    config: SandboxConfig,
    appcontainer: Arc<cache::CachedAppContainer>,
}

impl WindowsBackend {
    /// Create a new Windows backend.
    pub fn new(config: SandboxConfig) -> Result<Self, Error> {
        let appcontainer = cache::get(&config)?;
        Ok(Self {
            config,
            appcontainer,
        })
    }
}

impl Backend for WindowsBackend {
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

    fn explain(&self, ctx: &guardrail_core::ExplainCtx<'_>) -> Option<guardrail_core::Violation> {
        diagnostics::explain(ctx)
    }
}
