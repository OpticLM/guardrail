//! Windows Job Object creation and resource-limit setup.

#![cfg(windows)]

use std::mem::size_of;
use std::os::windows::io::{AsRawHandle, OwnedHandle};
use std::{io, ptr};

use guardrail_core::{Error, Result, SandboxConfig};
use windows_sys::Win32::System::JobObjects::{
    CreateJobObjectW, JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_JOB_MEMORY,
    JOB_OBJECT_LIMIT_JOB_TIME, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject,
};

use crate::handle::{bool_result, owned_handle_from_raw};

pub(crate) fn create(config: &SandboxConfig) -> Result<OwnedHandle> {
    // SAFETY: null security attributes and an unnamed job are valid inputs.
    // The returned raw handle is transferred into OwnedHandle below.
    let raw = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
    let job =
        unsafe { owned_handle_from_raw(raw) }.map_err(|err| Error::confinement("job", err))?;

    let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

    if let Some(bytes) = config.limits.memory_bytes {
        info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
        info.JobMemoryLimit = usize::try_from(bytes).map_err(|_| {
            Error::confinement(
                "job",
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "memory limit does not fit Windows JobMemoryLimit",
                ),
            )
        })?;
    }

    if let Some(max_processes) = config.limits.max_processes {
        info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        info.BasicLimitInformation.ActiveProcessLimit =
            u32::try_from(max_processes).map_err(|_| {
                Error::confinement(
                    "job",
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "max_processes does not fit Windows ActiveProcessLimit",
                    ),
                )
            })?;
    }

    if let Some(seconds) = config.limits.cpu_time_secs {
        let ticks = seconds
            .checked_mul(10_000_000)
            .and_then(|ticks| i64::try_from(ticks).ok())
            .ok_or_else(|| {
                Error::confinement(
                    "job",
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "cpu_time_secs does not fit Windows PerJobUserTimeLimit",
                    ),
                )
            })?;
        info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_JOB_TIME;
        info.BasicLimitInformation.PerJobUserTimeLimit = ticks;
    }

    // SAFETY: `job` is a valid Job Object handle. `info` points to a properly
    // initialized JOBOBJECT_EXTENDED_LIMIT_INFORMATION for the duration of the
    // call, and the byte length matches the structure.
    let ok = unsafe {
        SetInformationJobObject(
            job.as_raw_handle(),
            JobObjectExtendedLimitInformation,
            &info as *const _ as *const _,
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    };
    bool_result(ok).map_err(|err| Error::confinement("job", err))?;

    Ok(job)
}
