//! Linux backend for `guardrail`.
//!
//! Applies confinement entirely in-process inside [`std::process::Command`]'s
//! `pre_exec` hook: resource limits via `setrlimit`, plus Landlock filesystem
//! rules and a seccomp-BPF filter for network and IPC. No external sandboxing
//! binary is used.

use std::os::unix::process::CommandExt;
use std::process::Command;

use guardrail_core::{Backend, Error, SandboxChild, SandboxConfig};

mod rlimit;

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
    fn spawn(&self, config: &SandboxConfig, mut command: Command) -> Result<SandboxChild, Error> {
        // Clone only the data the child closure needs. The closure runs in the
        // forked child, so it must own its inputs (no borrows of `config`).
        let limits = config.limits;

        // SAFETY: the closure runs after fork() and before execvp() in the
        // child. It performs only async-signal-safe syscalls (prctl, setrlimit)
        // and returns an io::Error instead of panicking.
        unsafe {
            command.pre_exec(move || {
                // (1) NO_NEW_PRIVS first: required for seccomp later, and a
                //     hardening measure on its own. prctl is async-signal-safe.
                set_no_new_privs()?;

                // (2) Resource limits.
                rlimit::apply(&limits)?;

                // (3) INSERTION POINT — later plans add, in this order:
                //       fs::apply(&fs_rules)?;        // plan 003 (Landlock)
                //       seccomp::apply(&filter)?;     // plans 004/005 (last)
                //     Apply seccomp LAST so its filter does not interfere with
                //     Landlock's own setup syscalls.

                Ok(())
            });
        }

        let child = command.spawn().map_err(Error::Spawn)?;
        Ok(SandboxChild::from(child))
    }
}

/// `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)`. Async-signal-safe.
fn set_no_new_privs() -> std::io::Result<()> {
    // SAFETY: prctl with PR_SET_NO_NEW_PRIVS takes scalar args only.
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
