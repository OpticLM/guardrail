//! The audit marker for opted-in sandboxes (`SandboxConfig::linux_audit_denials`).
//!
//! Guardrail does not read or expose denial logs. It marks the sandboxed
//! process tree so the host's own syscall auditing can select it: the marker
//! is inherited across `fork` and `execve`, printed as `per=` in every syscall
//! audit record, and matchable by an audit rule (`-F pers`). The seccomp
//! filters pin it (see `crate::seccomp`), so the tree cannot clear it.

use std::io;

use guardrail_core::{Error, Result};

/// `SHORT_INODE | WHOLE_SECONDS`: two `personality(2)` flags the kernel
/// defines but never reads.
pub(crate) const MARKER: u32 = 0x0300_0000;

/// Set [`MARKER`] on the calling process, keeping its other personality
/// bits. Fails when the host refuses `personality(2)`. Async-signal-safe.
pub(crate) fn mark() -> io::Result<()> {
    // SAFETY: personality takes one scalar argument; 0xffffffff only queries.
    let current = unsafe { libc::personality(0xffff_ffff) };
    let Ok(current) = libc::c_ulong::try_from(current) else {
        return Err(io::Error::last_os_error());
    };
    // SAFETY: personality takes one scalar argument.
    let previous = unsafe { libc::personality(current | libc::c_ulong::from(MARKER)) };
    if previous < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Verify that this host lets a process carry the marker. Runs [`mark`] in a
/// disposable forked child so the caller's own personality is untouched, and
/// so a host filter that kills on `personality(2)` only kills the child.
pub(crate) fn probe_marker_support() -> Result<()> {
    // SAFETY: fork takes no arguments; the child below only calls
    // async-signal-safe functions (personality, _exit) before exiting.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(Error::confinement(
            "audit marker probe",
            io::Error::last_os_error(),
        ));
    }
    if pid == 0 {
        let code = i32::from(mark().is_err());
        // SAFETY: immediate exit without running any Rust cleanup.
        unsafe { libc::_exit(code) };
    }

    let mut status: libc::c_int = 0;
    loop {
        // SAFETY: status is a valid out-pointer; pid is our direct child.
        let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
        if rc == pid {
            break;
        }
        let err = io::Error::last_os_error();
        if rc < 0 && err.raw_os_error() != Some(libc::EINTR) {
            return Err(Error::confinement("audit marker probe", err));
        }
    }

    if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
        return Ok(());
    }
    Err(Error::Unsupported(
        "linux_audit_denials marks sandboxed processes with personality(2), \
         which this host refuses (for example systemd LockPersonality= or a \
         container seccomp profile). Lift that restriction, or turn \
         linux_audit_denials off"
            .into(),
    ))
}
