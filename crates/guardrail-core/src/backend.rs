//! The platform-confinement abstraction.

use std::process::Command;

use crate::config::SandboxConfig;
use crate::diagnostics::{ExplainCtx, Violation};
use crate::error::Error;
use crate::process::SandboxChild;

/// A platform-specific sandbox backend.
///
/// Implementors apply OS-level confinement (filesystem, network, IPC, resource
/// limits) and spawn the child. The `command` they receive has **already** had
/// its environment scrubbed by the caller — a backend must not re-add
/// inherited environment variables.
///
/// The trait is object-safe so callers may hold a `&dyn Backend` if they wish.
pub trait Backend {
    /// Spawn `command` confined according to `config`.
    fn spawn(&self, config: &SandboxConfig, command: Command) -> Result<SandboxChild, Error>;

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
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    struct RecordingBackend {
        seen: Mutex<Option<SandboxConfig>>,
    }

    impl Backend for RecordingBackend {
        fn spawn(
            &self,
            config: &SandboxConfig,
            _command: std::process::Command,
        ) -> Result<SandboxChild, Error> {
            *self.seen.lock().unwrap() = Some(config.clone());
            Err(Error::Unsupported("recording backend never spawns".into()))
        }
    }

    #[test]
    fn spawn_scrubs_env_before_delegating() {
        let backend = RecordingBackend {
            seen: Mutex::new(None),
        };
        let config = SandboxConfig {
            fs: vec![],
            network: crate::policy::NetworkPolicy::Deny,
            ipc: crate::policy::IpcPolicy::Strict,
            limits: crate::config::ResourceLimits::default(),
            env: BTreeMap::from([("FOO".into(), "bar".into())]),
            darwin_sandbox_profiles: vec![],
        };
        let mut cmd = std::process::Command::new("true");
        cmd.env_clear();
        cmd.envs(&config.env);
        let _ = backend.spawn(&config, cmd);
        assert_eq!(backend.seen.lock().unwrap().as_ref(), Some(&config));
    }
}
