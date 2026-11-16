//! Audit markers for sandboxed process trees.
//!
//! Guardrail does not read or expose denial logs. It marks the sandboxed
//! process tree so the host's own syscall auditing can select it, in one of
//! two ways:
//!
//! * `SandboxConfig::linux_audit_denials` sets a `personality(2)` value. It is
//!   inherited across `fork` and `execve`, printed as `per=` in every syscall
//!   audit record, and matchable by an audit rule (`-F pers`). The seccomp
//!   filters pin it (see `crate::seccomp`), so the tree cannot clear it.
//! * `SandboxConfig::linux_audit_group` adds a supplementary group, matchable
//!   with `-F gid=`. It needs `CAP_SETGID` in the host process and no pin: the
//!   sandbox's user namespace denies `setgroups(2)` for good, so the tree
//!   cannot drop it.

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

/// Verify that this host lets a process carry the marker.
pub(crate) fn probe_marker_support() -> Result<()> {
    match probe_in_child(mark)? {
        None => Ok(()),
        Some(detail) => Err(Error::Unsupported(format!(
            "linux_audit_denials marks sandboxed processes with personality(2), \
             which this host refuses: {detail} (for example systemd \
             LockPersonality= or a container seccomp profile). Lift that \
             restriction, or turn linux_audit_denials off"
        ))),
    }
}

/// The supplementary groups a sandboxed child installs to carry the audit
/// group: the host's own groups plus `group`. Built in the parent, where
/// allocation is allowed, and verified to be installable on this host.
pub(crate) fn prepare_groups(group: libc::gid_t) -> Result<Vec<libc::gid_t>> {
    let groups = groups_with(group).map_err(|e| Error::confinement("audit group", e))?;
    match probe_in_child(|| set_groups(&groups))? {
        None => Ok(groups),
        Some(detail) => Err(Error::Unsupported(format!(
            "linux_audit_group adds a supplementary group to sandboxed \
             processes, which needs CAP_SETGID in the host process: {detail}. \
             Grant it (for example run as root), or leave linux_audit_group \
             unset"
        ))),
    }
}

/// The calling process's supplementary groups plus `group`.
fn groups_with(group: libc::gid_t) -> io::Result<Vec<libc::gid_t>> {
    // SAFETY: a zero size with a null list only returns the group count.
    let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    let Ok(len) = usize::try_from(count) else {
        return Err(io::Error::last_os_error());
    };
    let mut groups: Vec<libc::gid_t> = vec![0; len];
    // SAFETY: `groups` has room for the `count` entries the kernel may write.
    let written = unsafe { libc::getgroups(count, groups.as_mut_ptr()) };
    let Ok(written) = usize::try_from(written) else {
        return Err(io::Error::last_os_error());
    };
    groups.truncate(written);
    if !groups.contains(&group) {
        groups.push(group);
    }
    Ok(groups)
}

/// Install `groups` as the calling process's supplementary groups. Needs
/// `CAP_SETGID`. One raw syscall, so it is async-signal-safe; glibc's wrapper
/// synchronizes every thread and is not.
pub(crate) fn set_groups(groups: &[libc::gid_t]) -> io::Result<()> {
    // SAFETY: `groups` is valid for `groups.len()` entries for the duration
    // of the call, and the kernel only reads it.
    let rc = unsafe { libc::syscall(libc::SYS_setgroups, groups.len(), groups.as_ptr()) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Run `setup` in a disposable forked child, so the caller's own process
/// state is untouched and a host filter that kills on the syscall only kills
/// the child. `Ok(None)` when `setup` succeeded, otherwise why it did not.
fn probe_in_child(setup: impl FnOnce() -> io::Result<()>) -> Result<Option<String>> {
    // SAFETY: fork takes no arguments; the child below only calls
    // async-signal-safe functions (personality or setgroups, then _exit)
    // before exiting.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(Error::confinement(
            "audit marker probe",
            io::Error::last_os_error(),
        ));
    }
    if pid == 0 {
        let code = match setup() {
            Ok(()) => 0,
            Err(err) => err.raw_os_error().unwrap_or(libc::EIO),
        };
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
        return Ok(None);
    }
    Ok(Some(if libc::WIFEXITED(status) {
        io::Error::from_raw_os_error(libc::WEXITSTATUS(status)).to_string()
    } else {
        "probe child terminated abnormally".into()
    }))
}
