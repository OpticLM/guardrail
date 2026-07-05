//! The platform-confinement abstraction.

use std::process::Command;

use crate::diagnostics::{ExplainCtx, Violation};
use crate::error::Error;
use crate::process::SandboxChild;

/// A platform-specific sandbox backend.
///
/// Implementors apply OS-level confinement (filesystem, network, IPC, resource
/// limits) and spawn the child according to the immutable configuration they
/// were constructed with. A backend must clear the command's inherited
/// environment before applying the configuration environment.
///
/// The trait is object-safe so callers may hold a `&dyn Backend` if they wish.
pub trait Backend {
    /// Spawn `command` confined according to this backend's stored config.
    fn spawn(&self, command: Command) -> Result<SandboxChild, Error>;

    /// Best-effort explanation of why `ctx.status` likely indicates a policy
    /// violation under `ctx.config`. Returns `None` on success or when the
    /// failure could not be attributed to a policy.
    ///
    /// The default is a platform-agnostic heuristic ([`portable_explain`]);
    /// platform backends override it to add signal- or Seatbelt-specific
    /// attribution. Like all diagnostics in this crate it is heuristic — the
    /// parent cannot observe the exact syscall or path a backend denied — so
    /// this narrows the cause from the exit status, the active configuration,
    /// and any captured output in `ctx`.
    ///
    /// [`portable_explain`]: crate::diagnostics::portable_explain
    fn explain(&self, ctx: &ExplainCtx<'_>) -> Option<Violation> {
        crate::diagnostics::portable_explain(ctx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SandboxConfig;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    struct RecordingBackend {
        config: SandboxConfig,
        seen_env: Mutex<Option<BTreeMap<String, String>>>,
    }

    impl Backend for RecordingBackend {
        fn spawn(&self, mut command: std::process::Command) -> Result<SandboxChild, Error> {
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
            ipc: crate::policy::IpcPolicy::Strict,
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
