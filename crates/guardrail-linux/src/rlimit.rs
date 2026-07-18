//! Resource limits via `setrlimit(2)`. These are per-process caps inherited by
//! descendants, not aggregate budgets for the sandboxed tree; `RLIMIT_NPROC`
//! counts all processes/threads of the real UID and is not enforced for
//! privileged users (see [`guardrail_core::ResourceLimits`]).
//!
//! Applied inside `pre_exec`, so every
//! function here must be async-signal-safe (only raw `libc` calls, no
//! allocation, no panics that unwind across the FFI boundary).

use std::io;

use guardrail_core::ResourceLimits;

// libc declares setrlimit's resource as c_int on musl and as this target type
// on GNU/uClibc.
#[cfg(target_env = "musl")]
type RlimitResource = libc::c_int;
#[cfg(not(target_env = "musl"))]
type RlimitResource = libc::__rlimit_resource_t;

/// Apply `limits` to the current process. Called from within `pre_exec` in the
/// freshly-forked child, before `execvp`.
///
/// Returns the first `errno`-based error encountered. `None` fields are skipped.
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

/// Set soft = hard = `value` for one resource.
fn set_one(resource: RlimitResource, value: u64) -> io::Result<()> {
    let rl = libc::rlimit {
        rlim_cur: value as libc::rlim_t,
        rlim_max: value as libc::rlim_t,
    };
    // SAFETY: `rl` is a valid, fully-initialized rlimit for the duration of the
    // call; `setrlimit` does not retain the pointer.
    let rc = unsafe { libc::setrlimit(resource, &rl) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
