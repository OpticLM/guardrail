//! macOS backend support for `guardrail`.
//!
//! Profile generation is platform-independent and tested on Linux. Native
//! Seatbelt application is available on macOS.

pub mod diagnostics;
#[allow(dead_code)]
mod profile;
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod rlimit;
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod seatbelt;

#[cfg(target_os = "macos")]
use std::os::unix::process::CommandExt;
use std::process::Command;

use guardrail_core::{Backend, Error, SandboxChild, SandboxConfig};

/// The macOS sandbox backend.
#[derive(Debug, Default, Clone)]
pub struct MacosBackend {
    _private: (),
}

impl MacosBackend {
    /// Create a new macOS backend.
    pub fn new() -> Self {
        Self::default()
    }
}

impl Backend for MacosBackend {
    #[cfg(target_os = "macos")]
    fn spawn(&self, config: &SandboxConfig, mut command: Command) -> Result<SandboxChild, Error> {
        let seatbelt_profile = seatbelt::resolve(config)?;
        let limits = config.limits;

        // SAFETY: the closure runs after fork() and before execvp() in the
        // child. It only applies rlimits and calls Apple's sandbox_init wrapper,
        // returning io::Error instead of panicking.
        unsafe {
            command.pre_exec(move || {
                rlimit::apply(&limits)?;
                seatbelt::apply(&seatbelt_profile).map_err(std::io::Error::other)?;
                Ok(())
            });
        }

        let child = command.spawn().map_err(Error::Spawn)?;
        Ok(SandboxChild::from(child))
    }

    #[cfg(not(target_os = "macos"))]
    fn spawn(&self, _config: &SandboxConfig, _command: Command) -> Result<SandboxChild, Error> {
        Err(Error::Unsupported(
            "guardrail-macos backend only supports target_os = \"macos\"".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use guardrail_core::SandboxBuilder;
    #[cfg(not(target_os = "macos"))]
    use guardrail_core::{Backend, Error};

    #[test]
    fn crate_smoke_test_builds_a_default_config() {
        let config = SandboxBuilder::new().build();
        assert!(config.fs.is_empty());
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn backend_returns_unsupported_on_non_macos() {
        let backend = super::MacosBackend::new();
        let config = SandboxBuilder::new()
            .darwin_sandbox_profile("/definitely/missing/profile.sb")
            .build();

        let err = backend
            .spawn(&config, std::process::Command::new("true"))
            .unwrap_err();

        assert!(matches!(
            err,
            Error::Unsupported(message)
                if message == "guardrail-macos backend only supports target_os = \"macos\""
        ));
    }
}
