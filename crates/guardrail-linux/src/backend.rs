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

                // (4) Descriptor hygiene: mark everything above stderr
                //     close-on-exec. Runs after the steps above so descriptors
                //     they open along the way are covered too, and before
                //     seccomp so the filter cannot interfere with the syscall.
                scrub_inherited_fds()?;

                // (5) Seccomp is applied LAST so its filters do not interfere
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

/// Mark every descriptor above stderr close-on-exec so `execve` closes them
/// atomically. Landlock and seccomp cannot revoke access to descriptors the
/// parent already holds open (files, sockets, pipes), so an inherited
/// descriptor would bypass the whole policy.
///
/// Descriptors are flagged rather than closed because the standard library's
/// fork/exec machinery still needs its (already close-on-exec) exec-error
/// pipe after this closure returns; stdio was `dup2`ed onto 0–2 before any
/// `pre_exec` closure runs, so it is unaffected. `close_range(2)` is
/// async-signal-safe; `CLOSE_RANGE_CLOEXEC` exists since Linux 5.11, and every
/// kernel that passes the Landlock probe (5.13+) has it, so there is no
/// fallback path — fail closed instead. The raw syscall avoids the glibc
/// 2.34+ / musl wrapper requirement.
fn scrub_inherited_fds() -> std::io::Result<()> {
    // SAFETY: close_range takes scalar args only and touches no memory.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_close_range,
            3,
            libc::c_uint::MAX,
            libc::CLOSE_RANGE_CLOEXEC,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
