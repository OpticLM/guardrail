use std::os::unix::process::CommandExt;
use std::process::Command;

use guardrail_core::{Backend, Error, Result, SandboxChild, SandboxConfig};

use crate::{profile, rlimit, seatbelt};

/// The macOS sandbox backend.
pub struct MacosBackend {
    config: SandboxConfig,
    seatbelt_profile: profile::SeatbeltProfile,
}

impl MacosBackend {
    /// Create a new macOS backend.
    pub fn new(config: SandboxConfig) -> Result<Self> {
        let seatbelt_profile = seatbelt::resolve(&config)?;
        Ok(Self {
            config,
            seatbelt_profile,
        })
    }
}

impl Backend for MacosBackend {
    fn spawn(&self, mut command: Command) -> Result<SandboxChild> {
        command.env_clear();
        command.envs(&self.config.env);

        let seatbelt_profile = self.seatbelt_profile.clone();
        let limits = self.config.limits;

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
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use guardrail_core::{IpcPolicy, NetworkPolicy, ResourceLimits, SandboxConfig};

    #[test]
    fn crate_smoke_test_builds_a_default_config() {
        let config = SandboxConfig {
            fs: vec![],
            network: NetworkPolicy::Deny,
            ipc: IpcPolicy::Strict,
            limits: ResourceLimits::default(),
            env: BTreeMap::new(),
            darwin_sandbox_profiles: vec![],
            windows_cache_namespace: None,
        };
        assert!(config.fs.is_empty());
    }
}
