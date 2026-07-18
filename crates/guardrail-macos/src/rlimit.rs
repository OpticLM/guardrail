//! Resource limits via `setrlimit(2)`.

use std::io;

use guardrail_core::ResourceLimits;

type RlimitResource = libc::c_int;

/// Apply `limits` to the current process. Called from within `pre_exec` in the
/// freshly-forked child, before the Seatbelt launcher is execed.
pub(crate) fn apply(limits: &ResourceLimits) -> io::Result<()> {
    if let Some(bytes) = limits.memory_bytes {
        set_one(libc::RLIMIT_AS, bytes)?;
    }
    if let Some(secs) = limits.cpu_time_secs {
        set_one(libc::RLIMIT_CPU, secs)?;
    }
    if let Some(n) = limits.max_processes {
        set_one(libc::RLIMIT_NPROC, n)?;
    }
    Ok(())
}

fn set_one(resource: RlimitResource, value: u64) -> io::Result<()> {
    let rl = libc::rlimit {
        rlim_cur: value as libc::rlim_t,
        rlim_max: value as libc::rlim_t,
    };
    // SAFETY: `rl` is fully initialized and `setrlimit` does not retain the
    // pointer beyond this call.
    let rc = unsafe { libc::setrlimit(resource, &rl) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
