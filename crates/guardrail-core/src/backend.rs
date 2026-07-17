//! The platform-confinement abstraction.

use std::process::Command;

use crate::error::Result;
use crate::process::SandboxChild;

/// A platform-specific sandbox backend.
///
/// Implementors apply OS-level confinement (filesystem, network, IPC, resource
/// limits) and spawn the child according to the immutable configuration they
/// were constructed with. A backend must clear the command's inherited
/// environment before applying the configuration environment, and must keep
/// the parent's file descriptors or handles from leaking into the child:
/// only the standard streams may cross the sandbox boundary. Policies cannot
/// revoke access to descriptors that are already open, so an inherited
/// descriptor would bypass them.
pub trait Backend {
    /// Probe whether the running machine appears to support this backend.
    ///
    /// Returns [`Error::Unsupported`] when a required OS or kernel feature
    /// cannot be probed. A successful probe is not proof that a later spawn
    /// will succeed: runtime state or an ambient sandbox may still block
    /// confinement. In particular, Linux only probes whether the kernel
    /// reports the seccomp `Trap` action; it cannot prove that installing the
    /// backend's filter will be permitted.
    ///
    /// Backends still fail closed during construction or spawn, so calling
    /// this first is optional. It exists to let applications detect known
    /// incompatibilities up front and degrade deliberately.
    ///
    /// [`Error::Unsupported`]: crate::Error::Unsupported
    fn probe_support() -> Result<()>
    where
        Self: Sized;

    /// Spawn `command` confined according to this backend's stored config.
    fn spawn(&self, command: Command) -> Result<SandboxChild>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SandboxConfig;
    use crate::error::Error;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    struct RecordingBackend {
        config: SandboxConfig,
        seen_env: Mutex<Option<BTreeMap<String, String>>>,
    }

    impl Backend for RecordingBackend {
        fn probe_support() -> Result<()> {
            Ok(())
        }

        fn spawn(&self, mut command: std::process::Command) -> Result<SandboxChild> {
            command.env_clear();
            command.envs(&self.config.env);
            let seen = command
                .get_envs()
                .filter_map(|(key, value)| {
                    value.map(|value| {
                        (
                            key.to_string_lossy().into_owned(),
                            value.to_string_lossy().into_owned(),
                        )
                    })
                })
                .collect();
            *self.seen_env.lock().unwrap() = Some(seen);
            Err(Error::Unsupported("recording backend never spawns".into()))
        }
    }

    #[test]
    fn spawn_scrubs_env_before_delegating() {
        let config = SandboxConfig {
            fs: vec![],
            network: crate::policy::NetworkPolicy::Deny,
            linux_ipc: crate::policy::IpcPolicy::Strict,
            limits: crate::config::ResourceLimits::default(),
            env: BTreeMap::from([("FOO".into(), "bar".into())]),
            darwin_sandbox_profiles: vec![],
            windows_cache_namespace: None,
        };
        let backend = RecordingBackend {
            config: config.clone(),
            seen_env: Mutex::new(None),
        };
        let mut cmd = std::process::Command::new("true");
        cmd.env("SHOULD_NOT_SURVIVE", "1");
        let _ = backend.spawn(cmd);
        assert_eq!(backend.seen_env.lock().unwrap().as_ref(), Some(&config.env));
    }
}
