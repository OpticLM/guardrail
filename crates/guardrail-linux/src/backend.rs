use std::os::unix::process::CommandExt;
use std::process::Command;

use guardrail_core::{Backend, Error, Result, SandboxChild, SandboxConfig};

use crate::{fs, rlimit, seccomp, support};

/// The Linux sandbox backend.
pub struct LinuxBackend {
    config: SandboxConfig,
    fs_rules: fs::CompiledRules,
    seccomp_programs: Vec<seccompiler::BpfProgram>,
}

impl LinuxBackend {
    /// Create a new Linux backend.
    ///
    /// Fails closed with [`Error::Unsupported`] when the running kernel cannot
    /// enforce Landlock or fails the seccomp action-availability probe (see
    /// [`Backend::probe_support`]).
    pub fn new(config: SandboxConfig) -> Result<Self> {
        Self::probe_support()?;
        let fs_rules = fs::compile(&config.fs)?;
        let seccomp_programs = seccomp::build(&config)?;
        Ok(Self {
            config,
            fs_rules,
            seccomp_programs,
        })
    }
}

impl Backend for LinuxBackend {
    fn probe_support() -> Result<()> {
        support::probe_required_features()
    }

    fn spawn(&self, mut command: Command) -> Result<SandboxChild> {
        command.env_clear();
        command.envs(&self.config.env);

        // Clone only the data the child closure needs. The closure runs in the
        // forked child, so it must own its inputs (no borrows of `self`).
        let limits = self.config.limits;
        let fs_rules = self.fs_rules.clone();
        let seccomp_programs = self.seccomp_programs.clone();

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

                // (4) Seccomp is applied LAST so its filters do not interfere
                //     with Landlock's own setup syscalls.
                //     The BPF programs were built in the parent;
                //     only install them here.
                seccomp::apply(&seccomp_programs).map_err(std::io::Error::other)?;

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
