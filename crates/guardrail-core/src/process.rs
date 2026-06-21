//! Handle to a running sandboxed process.

use std::process::{Child, ExitStatus};

#[cfg(windows)]
use std::os::windows::io::{AsRawHandle, OwnedHandle};

/// A handle to a spawned, sandboxed child process.
///
/// Most backends wrap [`std::process::Child`]. Windows can instead wrap raw
/// process and Job Object handles so the process tree dies with the sandbox.
#[derive(Debug)]
pub struct SandboxChild {
    inner: SandboxChildInner,
}

#[derive(Debug)]
enum SandboxChildInner {
    Child(Child),
    #[cfg(windows)]
    WindowsRaw {
        process: OwnedHandle,
        job: OwnedHandle,
        pid: u32,
    },
}

impl SandboxChild {
    /// The OS-assigned process id of the child.
    pub fn id(&self) -> u32 {
        match &self.inner {
            SandboxChildInner::Child(child) => child.id(),
            #[cfg(windows)]
            SandboxChildInner::WindowsRaw { pid, .. } => *pid,
        }
    }

    /// Wait for the child to exit, returning its status.
    pub fn wait(&mut self) -> std::io::Result<ExitStatus> {
        match &mut self.inner {
            SandboxChildInner::Child(child) => child.wait(),
            #[cfg(windows)]
            SandboxChildInner::WindowsRaw { process, .. } => windows_wait(process),
        }
    }

    /// Attempt to kill the child immediately.
    pub fn kill(&mut self) -> std::io::Result<()> {
        match &mut self.inner {
            SandboxChildInner::Child(child) => child.kill(),
            #[cfg(windows)]
            SandboxChildInner::WindowsRaw { job, .. } => windows_kill_job(job),
        }
    }

    /// Borrow the underlying [`Child`] (e.g. to take its stdio handles).
    pub fn inner_mut(&mut self) -> &mut Child {
        match &mut self.inner {
            SandboxChildInner::Child(child) => child,
            #[cfg(windows)]
            SandboxChildInner::WindowsRaw { .. } => {
                panic!("raw Windows SandboxChild has no std::process::Child")
            }
        }
    }

    /// Consume the handle and return the underlying [`Child`].
    pub fn into_inner(self) -> Child {
        match self.inner {
            SandboxChildInner::Child(child) => child,
            #[cfg(windows)]
            SandboxChildInner::WindowsRaw { .. } => {
                panic!("raw Windows SandboxChild has no std::process::Child")
            }
        }
    }

    /// Construct a Windows child from already-owned process and Job handles.
    ///
    /// # Safety
    ///
    /// `process` must be a waitable process handle for `pid`, and `job` must be
    /// the Job Object that owns that process tree. Both handles must be unique
    /// owned handles whose lifetimes are transferred to this `SandboxChild`.
    #[cfg(windows)]
    pub unsafe fn from_windows_handles(process: OwnedHandle, job: OwnedHandle, pid: u32) -> Self {
        Self {
            inner: SandboxChildInner::WindowsRaw { process, job, pid },
        }
    }
}

impl From<Child> for SandboxChild {
    fn from(inner: Child) -> Self {
        SandboxChild {
            inner: SandboxChildInner::Child(inner),
        }
    }
}

#[cfg(windows)]
fn windows_wait(process: &OwnedHandle) -> std::io::Result<ExitStatus> {
    use std::os::windows::process::ExitStatusExt;

    const WAIT_OBJECT_0: u32 = 0;
    const WAIT_FAILED: u32 = 0xFFFF_FFFF;
    const INFINITE: u32 = 0xFFFF_FFFF;

    // SAFETY: `process` is an owned process handle supplied by the Windows
    // backend. It remains valid for the duration of this wait call.
    let wait = unsafe { WaitForSingleObject(process.as_raw_handle(), INFINITE) };
    match wait {
        WAIT_OBJECT_0 => {
            let mut exit_code = 0;
            // SAFETY: the process has signaled, and `exit_code` is a valid
            // out-pointer for the OS to write the u32 exit status.
            let ok = unsafe { GetExitCodeProcess(process.as_raw_handle(), &mut exit_code) };
            if ok == 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(ExitStatus::from_raw(exit_code))
        }
        WAIT_FAILED => Err(std::io::Error::last_os_error()),
        other => Err(std::io::Error::other(format!(
            "unexpected WaitForSingleObject result {other}"
        ))),
    }
}

#[cfg(windows)]
fn windows_kill_job(job: &OwnedHandle) -> std::io::Result<()> {
    // SAFETY: `job` is an owned Job Object handle kept alive by SandboxChild.
    // TerminateJobObject accepts this handle and does not take ownership.
    let ok = unsafe { TerminateJobObject(job.as_raw_handle(), 1) };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(windows)]
unsafe extern "system" {
    fn WaitForSingleObject(hhandle: std::os::windows::io::RawHandle, dwmilliseconds: u32) -> u32;
    fn GetExitCodeProcess(hprocess: std::os::windows::io::RawHandle, lpexitcode: *mut u32) -> i32;
    fn TerminateJobObject(hjob: std::os::windows::io::RawHandle, uexitcode: u32) -> i32;
}
