//! Windows backend for `guardrail`.
//!
//! This crate is a platform backend placeholder until the AppContainer and Job
//! Object confinement implementation lands.

use std::process::Command;

use guardrail_core::{Backend, Error, SandboxChild, SandboxConfig};

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
    fn spawn(&self, _config: &SandboxConfig, _command: Command) -> Result<SandboxChild, Error> {
        Err(Error::Unsupported(
            "guardrail-windows confinement is not implemented yet; run plans 008-009".into(),
        ))
    }
}
