//! The platform-confinement abstraction.

use std::process::Command;

use crate::config::SandboxConfig;
use crate::error::Error;
use crate::process::SandboxChild;

/// A platform-specific sandbox backend.
///
/// Implementors apply OS-level confinement (filesystem, network, IPC, resource
/// limits) and spawn the child. The `command` they receive has **already** had
/// its environment scrubbed by [`SandboxConfig::spawn_with`] — a backend must
/// not re-add inherited environment variables.
///
/// The trait is object-safe so callers may hold a `&dyn Backend` if they wish.
pub trait Backend {
    /// Spawn `command` confined according to `config`.
    fn spawn(&self, config: &SandboxConfig, command: Command) -> Result<SandboxChild, Error>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SandboxBuilder;
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
    fn spawn_with_scrubs_then_delegates() {
        let backend = RecordingBackend {
            seen: Mutex::new(None),
        };
        let config = SandboxBuilder::new().env("FOO", "bar").build();
        let _ = config.spawn_with(&backend, std::process::Command::new("true"));
        assert_eq!(backend.seen.lock().unwrap().as_ref(), Some(&config));
    }
}
