//! Linux backend for `guardrail`.
//!
//! Applies confinement entirely in-process inside [`std::process::Command`]'s
//! `pre_exec` hook: resource limits via `setrlimit`, plus Landlock filesystem
//! rules and a seccomp-BPF filter for network and IPC. No external sandboxing
//! binary is used.

use std::process::Command;

use guardrail_core::{Backend, Error, SandboxChild, SandboxConfig};

#[cfg(target_os = "linux")]
pub mod diagnostics;

#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;

#[cfg(target_os = "linux")]
mod fs;
#[cfg(target_os = "linux")]
mod rlimit;
#[cfg(target_os = "linux")]
mod seccomp;

/// The Linux sandbox backend.
#[derive(Debug, Default, Clone)]
pub struct LinuxBackend {
    _private: (),
}

impl LinuxBackend {
    /// Create a new Linux backend.
    pub fn new() -> Self {
        Self::default()
    }
}

impl Backend for LinuxBackend {
    #[cfg(target_os = "linux")]
    fn spawn(&self, config: &SandboxConfig, mut command: Command) -> Result<SandboxChild, Error> {
        // Clone only the data the child closure needs. The closure runs in the
        // forked child, so it must own its inputs (no borrows of `config`).
        let limits = config.limits;
        let fs_rules = config.fs.clone();
        let seccomp_program = seccomp::build(config)?;

        // SAFETY: the closure runs after fork() and before execvp() in the
        // child. NO_NEW_PRIVS and the rlimit calls are async-signal-safe; the
        // Landlock ruleset construction allocates, which is acceptable in this
        // single-threaded post-fork child (glibc releases the malloc arena
        // locks across fork) and matches established in-process sandbox crates.
        // It returns an io::Error instead of panicking.
        unsafe {
            command.pre_exec(move || {
                // (1) NO_NEW_PRIVS first: required for seccomp later, and a
                //     hardening measure on its own. prctl is async-signal-safe.
                set_no_new_privs()?;

                // (2) Resource limits.
                rlimit::apply(&limits)?;

                // (3) Filesystem confinement via Landlock. `fs::apply` returns
                //     our structured Error; bridge it to io::Error because
                //     `pre_exec` closures must return `io::Result`.
                fs::apply(&fs_rules).map_err(std::io::Error::other)?;

                // (4) Seccomp is applied LAST so its filter does not interfere
                //     with Landlock's own setup syscalls.
                //     The BPF program was built in the parent;
                //     only install it here.
                if let Some(program) = &seccomp_program {
                    seccomp::apply(program).map_err(std::io::Error::other)?;
                }

                Ok(())
            });
        }

        let child = command.spawn().map_err(Error::Spawn)?;
        Ok(SandboxChild::from(child))
    }

    #[cfg(not(target_os = "linux"))]
    fn spawn(&self, _config: &SandboxConfig, _command: Command) -> Result<SandboxChild, Error> {
        Err(Error::Unsupported(
            "guardrail-linux is only available on Linux".into(),
        ))
    }
}

/// `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)`. Async-signal-safe.
#[cfg(target_os = "linux")]
fn set_no_new_privs() -> std::io::Result<()> {
    // SAFETY: prctl with PR_SET_NO_NEW_PRIVS takes scalar args only.
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
