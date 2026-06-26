//! Handle to a running sandboxed process.

use std::process::{Child, ExitStatus};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

#[cfg(windows)]
use std::any::Any;
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
        _guards: Vec<Box<dyn Any + Send>>,
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
        // SAFETY: delegated to from_windows_handles_with_guards with no extra
        // cleanup guards.
        unsafe { Self::from_windows_handles_with_guards(process, job, pid, Vec::new()) }
    }

    /// Construct a Windows child and keep backend cleanup guards alive with it.
    ///
    /// # Safety
    ///
    /// Same requirements as [`Self::from_windows_handles`]. Each guard must be
    /// safe to drop after the process and Job Object handles are dropped.
    #[cfg(windows)]
    pub unsafe fn from_windows_handles_with_guards(
        process: OwnedHandle,
        job: OwnedHandle,
        pid: u32,
        guards: Vec<Box<dyn Any + Send>>,
    ) -> Self {
        Self {
            inner: SandboxChildInner::WindowsRaw {
                process,
                job,
                pid,
                _guards: guards,
            },
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

/// `Send + Sync` handle to a running sandboxed child, safe to share across
/// threads so `wait()` (blocking, on a worker thread) and `kill()` (another
/// thread) can run concurrently. Enforces the OS invariant that the pid is not
/// signalled after `wait()` reaps it.
///
/// Built from a single-owner [`SandboxChild`]; async/FFI bindings (e.g. the
/// napi binding) wrap this so they get the wait/kill coordination once instead
/// of re-deriving it per binding. The single-owner [`SandboxChild`] stays
/// `&mut self` and remains what [`Backend`](crate::Backend)::spawn returns;
/// `SharedSandboxChild` is opt-in for callers that need sharing.
#[derive(Debug, Clone)]
pub struct SharedSandboxChild {
    pid: u32,
    // `Option` so `wait()` can take the child out for the duration of the
    // blocking wait without holding the lock (which would deadlock `kill()`).
    inner: Arc<Mutex<Option<SandboxChild>>>,
    // Set after `wait()` reaps the child. `kill()` reads it to avoid signalling
    // a pid the OS has freed and may have reassigned once `wait()` returns.
    reaped: Arc<AtomicBool>,
}

impl SharedSandboxChild {
    /// Wrap a single-owner [`SandboxChild`] in a shareable handle.
    pub fn new(child: SandboxChild) -> Self {
        let pid = child.id();
        Self {
            pid,
            inner: Arc::new(Mutex::new(Some(child))),
            reaped: Arc::new(AtomicBool::new(false)),
        }
    }

    /// The OS-assigned process id of the child.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Wait for the child to exit, returning its status.
    ///
    /// Takes the child out of the mutex for the duration of the blocking wait so
    /// a concurrent [`kill`](Self::kill) is not blocked. Calling `wait()` more
    /// than once returns an error: `waitpid` can only reap a pid once.
    pub fn wait(&self) -> std::io::Result<ExitStatus> {
        // Take the child OUT of the mutex so the blocking wait does not hold the
        // lock (kill() needs to acquire it). If it is already gone, wait() was
        // called twice.
        // Tolerate a poisoned mutex rather than unwrapping: if a concurrent
        // wait()/kill() panicked while holding `inner`, unwrapping would
        // propagate the poison panic and kill the other caller (and, via napi,
        // the Node thread). A `PoisonedMutexGuard` derefs to the inner
        // `Option<SandboxChild>` just like a clean guard, so `.take()` works.
        let mut child = self
            .inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .ok_or_else(|| std::io::Error::other("wait() has already been called on this child"))?;
        let status = child.wait()?;
        // `waitpid` reaps the pid atomically with this return, so mark it reaped
        // before anything else: a concurrent `kill()` must not `SIGKILL` the
        // now-free pid. (On error we leave it false: the child's state is
        // unknown and the kill fallback remains the intended behavior.)
        self.reaped.store(true, Ordering::SeqCst);
        Ok(status)
    }

    /// Kill the child immediately.
    ///
    /// - `wait()` not started → we still own the handle, kill it directly.
    /// - `wait()` in flight → the handle is gone but the child is still alive
    ///   (the pid has not been reaped), so on Unix this signals the pid. On
    ///   non-Unix platforms this is unsupported: the kill handle lives inside
    ///   the taken child and cannot be duplicated for concurrent use.
    /// - `wait()` already returned → the child has been reaped, so this is a
    ///   no-op. It must not signal a pid the OS may have reassigned.
    pub fn kill(&self) -> std::io::Result<()> {
        // See wait(): tolerate a poisoned mutex so a panic in the other caller
        // does not propagate here.
        match self.inner.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
            // wait() not started → we still own the handle.
            Some(child) => child.kill(),
            None => {
                // `inner` being None covers two cases: wait() is in flight
                // (child still alive, pid valid), or wait() already returned
                // (child reaped, pid freed and possibly reused by the OS). The
                // `reaped` flag distinguishes them — `waitpid` reaps the pid
                // atomically with its return, so `reaped` is set exactly when
                // the pid is no longer ours to signal.
                if self.reaped.load(Ordering::SeqCst) {
                    // Already reaped: the child is gone. Do not signal a pid the
                    // OS may have reassigned to an unrelated process.
                    return Ok(());
                }
                // wait() is in flight → the child is still alive and the pid has
                // not been reaped/reused, so signalling by pid is safe.
                #[cfg(unix)]
                {
                    // SAFETY: kill() with a pid and a signal takes scalar args.
                    // `reaped` is false, so `wait()` has not returned and the
                    // child is still alive — the pid has not been reaped/reused.
                    unsafe {
                        libc::kill(self.pid as libc::pid_t, libc::SIGKILL);
                    }
                    Ok(())
                }
                #[cfg(not(unix))]
                {
                    Err(std::io::Error::other(
                        "kill() while wait() is in flight is not supported on this platform",
                    ))
                }
            }
        }
    }
}

impl From<SandboxChild> for SharedSandboxChild {
    fn from(child: SandboxChild) -> Self {
        SharedSandboxChild::new(child)
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;
    use std::process::Command;
    use std::thread;
    use std::time::Duration;

    fn shared(mut cmd: Command) -> SharedSandboxChild {
        SharedSandboxChild::new(cmd.spawn().expect("spawn").into())
    }

    #[test]
    fn wait_twice_errors() {
        let child = shared(Command::new("true"));
        let status = child.wait().expect("first wait");
        assert!(status.success(), "true should exit cleanly, got {status:?}");

        let err = child.wait().expect_err("second wait must error");
        assert!(
            err.to_string().contains("already been called"),
            "expected an \"already been called\" error, got: {err}"
        );
    }

    #[test]
    fn kill_after_wait_is_noop() {
        let child = shared(Command::new("true"));
        let _ = child.wait().expect("wait");
        // The child has been reaped; kill() must not signal a pid the OS may
        // have freed and reassigned to an unrelated process.
        child
            .kill()
            .expect("kill() after wait() reaped the child is a no-op");
    }

    #[test]
    fn kill_during_wait_terminates() {
        let mut sleep = Command::new("sleep");
        sleep.arg("30");
        let child = shared(sleep);
        let waiter = child.clone();
        let handle = thread::spawn(move || waiter.wait().expect("wait returned err"));
        // Give the worker time to take the child out of the mutex and enter the
        // blocking waitpid. If we race and kill first, kill() goes through the
        // owned-handle path instead — the child still dies and the worker still
        // observes a signal status, so the assertion holds either way.
        thread::sleep(Duration::from_millis(100));
        child.kill().expect("kill during wait");
        let status = handle.join().expect("worker thread panicked");
        assert!(
            status.signal().is_some(),
            "expected the child to be terminated by a signal, got {status:?}"
        );
    }
}
