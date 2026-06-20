//! Linux backend for `guardrail`.
//!
//! Applies confinement entirely in-process inside [`std::process::Command`]'s
//! `pre_exec` hook: resource limits via `setrlimit`, plus Landlock filesystem
//! rules and a seccomp-BPF filter for network and IPC. No external sandboxing
//! binary is used.

use std::os::unix::process::CommandExt;
use std::process::Command;

use guardrail_core::{Backend, Error, SandboxChild, SandboxConfig};

mod fs;
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
        let fs_rules = config.fs.clone();

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

                // (4) INSERTION POINT — seccomp is applied LAST (plans 004/005)
                //     so its filter does not interfere with Landlock's own
                //     setup syscalls:
                //       seccomp::apply(&filter)?;
                //     Build the BPF program in the parent; only apply it here.

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
