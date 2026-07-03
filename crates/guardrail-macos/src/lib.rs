//! macOS backend support for `guardrail`.
//!
//! Profile generation is platform-independent and tested on Linux. Native
//! Seatbelt application is available on macOS.
//!
//! # Tips: common macOS runtime grants
//!
//! Guardrail generates only the rules you explicitly declare — no implicit
//! startup allowances. When sandboxing a macOS binary under Seatbelt with
//! `(deny default)`, you often need additional grants for the runtime
//! environment. The following patterns are common:
//!
//! **Filesystem**
//! - The root volume metadata (`/`) and `/var` for basic file-system probing.
//! - `/System/Cryptexes/OS` and `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld`
//!   for the dynamic linker on Apple Silicon.
//! - `/dev/dtracehelper` if the process or its runtime uses DTrace (with both
//!   `file-read-data`, `file-write-data`, and `file-ioctl` permissions).
//!
//! **Sysctl**
//! - `kern.bootargs`, `kern.osvariant_status`, `hw.ephemeral_storage`,
//!   `hw.pagesize_compat`, `machdep.ptrauth_enabled` are commonly queried
//!   by the runtime and well-known libraries.
//! - `security.mac.lockdown_mode_state` is read by some system frameworks.
//!
//! Use `.fs([FsAccess::ReadAllow(...), FsAccess::ExecuteAllow(...)])` for
//! binary and dylib paths, and grant sysctl access via a custom `.sb` profile
//! import or a manual `(allow sysctl-read (sysctl-name "kern.bootargs"))` rule
//! in your profile. See [`SandboxBuilder::darwin_sandbox_profiles`] for the
//! custom-profile escape hatch.

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

use guardrail_core::{Backend, Error, ExplainCtx, SandboxChild, SandboxConfig, Violation};

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

    // Not cfg-gated: the explanation is pure text/exit-status logic (the Unix
    // signal handling is delegated to core's cfg(unix) helper), so it compiles
    // everywhere and the Seatbelt denial parsing stays unit-testable on Linux.
    fn explain(&self, ctx: &ExplainCtx<'_>) -> Option<Violation> {
        diagnostics::explain(ctx)
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
            .darwin_sandbox_profiles(["/definitely/missing/profile.sb".into()])
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
