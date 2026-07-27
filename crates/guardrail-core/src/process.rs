//! Handle to a running sandboxed process.

use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, ExitStatus, Output};
use std::sync::{Arc, Mutex, MutexGuard};

#[cfg(windows)]
use std::any::Any;
#[cfg(windows)]
use std::os::windows::io::{AsRawHandle, OwnedHandle};

/// Parent-side ends of a Windows raw child's piped standard streams.
///
/// The Windows backend fills each field for a stream spawned with
/// [`StdioMode::Piped`](crate::StdioMode::Piped) and leaves it `None`
/// otherwise. Each handle wrapped here must be asynchronous (opened
/// overlapped), as [`From<OwnedHandle>`] for the `Child*` types requires.
#[cfg(windows)]
#[derive(Debug, Default)]
pub struct WindowsChildStdio {
    /// Write end of the child's stdin pipe.
    pub stdin: Option<ChildStdin>,
    /// Read end of the child's stdout pipe.
    pub stdout: Option<ChildStdout>,
    /// Read end of the child's stderr pipe.
    pub stderr: Option<ChildStderr>,
}

/// A handle to a spawned, sandboxed child process.
///
/// Most backends wrap [`std::process::Child`]. Windows can instead wrap raw
/// process and Job Object handles (plus the parent ends of any stdio pipes)
/// so the process tree dies with the sandbox.
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
        stdio: WindowsChildStdio,
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
    ///
    /// As with [`Child::wait`], the parent's end of the child's stdin pipe,
    /// if any, is closed first so a child reading stdin to EOF cannot
    /// deadlock against this wait.
    pub fn wait(&mut self) -> std::io::Result<ExitStatus> {
        match &mut self.inner {
            SandboxChildInner::Child(child) => child.wait(),
            #[cfg(windows)]
            SandboxChildInner::WindowsRaw { process, stdio, .. } => {
                drop(stdio.stdin.take());
                windows_wait(process)
            }
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

    /// Take the parent's write end of the child's stdin pipe, if the command
    /// piped stdin and it has not been taken already.
    ///
    /// Dropping the returned handle closes the pipe, signalling EOF to the
    /// child.
    pub fn take_stdin(&mut self) -> Option<ChildStdin> {
        match &mut self.inner {
            SandboxChildInner::Child(child) => child.stdin.take(),
            #[cfg(windows)]
            SandboxChildInner::WindowsRaw { stdio, .. } => stdio.stdin.take(),
        }
    }

    /// Take the parent's read end of the child's stdout pipe, if the command
    /// piped stdout and it has not been taken already.
    pub fn take_stdout(&mut self) -> Option<ChildStdout> {
        match &mut self.inner {
            SandboxChildInner::Child(child) => child.stdout.take(),
            #[cfg(windows)]
            SandboxChildInner::WindowsRaw { stdio, .. } => stdio.stdout.take(),
        }
    }

    /// Take the parent's read end of the child's stderr pipe, if the command
    /// piped stderr and it has not been taken already.
    pub fn take_stderr(&mut self) -> Option<ChildStderr> {
        match &mut self.inner {
            SandboxChildInner::Child(child) => child.stderr.take(),
            #[cfg(windows)]
            SandboxChildInner::WindowsRaw { stdio, .. } => stdio.stderr.take(),
        }
    }

    /// Wait for the child to exit, collecting its remaining piped output.
    ///
    /// As with [`Child::wait_with_output`], the child's stdin pipe (if any)
    /// is closed first to avoid deadlock, and only streams spawned with
    /// [`StdioMode::Piped`](crate::StdioMode::Piped) — and not already taken
    /// through the accessors above — contribute output bytes.
    pub fn wait_with_output(self) -> std::io::Result<Output> {
        match self.inner {
            SandboxChildInner::Child(child) => child.wait_with_output(),
            #[cfg(windows)]
            SandboxChildInner::WindowsRaw {
                process,
                job: _job,
                pid: _,
                mut stdio,
                _guards,
            } => {
                drop(stdio.stdin.take());
                let (stdout, stderr) =
                    windows_read_to_end(stdio.stdout.take(), stdio.stderr.take())?;
                let status = windows_wait(&process)?;
                // Mirror the struct's drop order: handles first, then stdio,
                // cleanup guards last.
                drop(process);
                drop(_job);
                drop(stdio);
                drop(_guards);
                Ok(Output {
                    status,
                    stdout,
                    stderr,
                })
            }
        }
    }

    /// Borrow the underlying [`std::process::Child`], if this handle wraps
    /// one.
    ///
    /// Children spawned by the Windows backend are backed by raw process and
    /// Job Object handles rather than a [`Child`], so for them this returns
    /// `None`. Prefer the portable methods on `SandboxChild`; reach for this
    /// only when an API exists solely on [`Child`], such as
    /// [`Child::try_wait`].
    ///
    /// ```no_run
    /// # fn main() -> std::io::Result<()> {
    /// use guardrail_core::SandboxChild;
    ///
    /// let mut child = SandboxChild::from(std::process::Command::new("tool").spawn()?);
    /// if let Some(inner) = child.as_child_mut() {
    ///     let exited = inner.try_wait()?.is_some();
    ///     println!("exited yet: {exited}");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn as_child_mut(&mut self) -> Option<&mut Child> {
        match &mut self.inner {
            SandboxChildInner::Child(child) => Some(child),
            #[cfg(windows)]
            SandboxChildInner::WindowsRaw { .. } => None,
        }
    }

    /// Consume the handle and return the underlying [`Child`], if this handle
    /// wraps one.
    ///
    /// Children spawned by the Windows backend are backed by raw process and
    /// Job Object handles rather than a [`Child`]; for them the intact handle
    /// comes back as the error, so a failed unwrap never loses the child.
    ///
    /// ```no_run
    /// # fn main() -> std::io::Result<()> {
    /// use guardrail_core::SandboxChild;
    ///
    /// let child = SandboxChild::from(std::process::Command::new("tool").spawn()?);
    /// let status = match child.try_into_child() {
    ///     // Backends other than Windows wrap a std Child.
    ///     Ok(mut inner) => inner.wait()?,
    ///     // Raw Windows children keep working through the returned handle.
    ///     Err(mut child) => child.wait()?,
    /// };
    /// println!("exited: {status}");
    /// # Ok(())
    /// # }
    /// ```
    pub fn try_into_child(self) -> Result<Child, Self> {
        match self.inner {
            SandboxChildInner::Child(child) => Ok(child),
            #[cfg(windows)]
            inner @ SandboxChildInner::WindowsRaw { .. } => Err(Self { inner }),
        }
    }

    /// Construct a Windows child from already-owned process and Job handles,
    /// plus the parent ends of any stdio pipes.
    ///
    /// # Safety
    ///
    /// `process` must be a waitable process handle for `pid`, and `job` must be
    /// the Job Object that owns that process tree. Both handles must be unique
    /// owned handles whose lifetimes are transferred to this `SandboxChild`.
    #[cfg(windows)]
    pub unsafe fn from_windows_handles(
        process: OwnedHandle,
        job: OwnedHandle,
        pid: u32,
        stdio: WindowsChildStdio,
    ) -> Self {
        // SAFETY: delegated to from_windows_handles_with_guards with no extra
        // cleanup guards.
        unsafe { Self::from_windows_handles_with_guards(process, job, pid, stdio, Vec::new()) }
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
        stdio: WindowsChildStdio,
        guards: Vec<Box<dyn Any + Send>>,
    ) -> Self {
        Self {
            inner: SandboxChildInner::WindowsRaw {
                process,
                job,
                pid,
                stdio,
                _guards: guards,
            },
        }
    }

    /// Duplicate the Job Object handle backing a raw Windows child, so a
    /// [`SharedSandboxChild`] can terminate the job without owning the child.
    #[cfg(windows)]
    fn try_clone_job(&self) -> Option<OwnedHandle> {
        match &self.inner {
            SandboxChildInner::Child(_) => None,
            SandboxChildInner::WindowsRaw { job, .. } => job.try_clone().ok(),
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
/// On Linux and macOS, `wait()` first blocks in `waitid(..., WNOWAIT)`, which
/// observes the exit *without* reaping: the child stays a zombie and the OS
/// cannot reuse its pid. The actual reap and transition to `Reaped` then happen
/// together under the same mutex `kill()` signals under, so `kill()` can never
/// see a pid that has been freed — the pid-reuse race between reaping and state
/// publication is closed by construction, not by timing. A failed wait moves
/// to an `Uncertain` state that permits only another wait, never a signal.
/// This type owns all waits for its child; process-wide code must not reap the
/// same child independently or change the `SIGCHLD` disposition concurrently.
///
/// Raw Windows children additionally carry a duplicated Job Object handle, so
/// `kill()` can terminate the tree in every state before the reap — including
/// while `wait()` is in flight. Handle-based termination cannot be redirected
/// by pid reuse, so it needs none of the Unix waitid coordination.
///
/// Built from a single-owner [`SandboxChild`]; async/FFI bindings (e.g. the
/// napi binding) wrap this so they get the wait/kill coordination once instead
/// of re-deriving it per binding. The single-owner [`SandboxChild`] stays
/// `&mut self` and remains what [`Backend`](crate::Backend)::spawn returns;
/// `SharedSandboxChild` is opt-in for callers that need sharing.
#[derive(Debug, Clone)]
pub struct SharedSandboxChild {
    pid: u32,
    #[cfg(windows)]
    job: Option<Arc<OwnedHandle>>,
    state: Arc<Mutex<SharedState>>,
}

#[derive(Debug)]
enum SharedState {
    Ready(SandboxChild),
    // The child handle is owned by wait(). can_signal is true only when Linux
    // or macOS is expected to retain waitable status until the guarded reap.
    Waiting { can_signal: bool },
    // A wait failed, so the child handle is retained for a retry but its pid is
    // not safe to signal: the OS or another waiter may already have reaped it.
    Uncertain(SandboxChild),
    Reaped,
}

impl SharedSandboxChild {
    /// Wrap a single-owner [`SandboxChild`] in a shareable handle.
    pub fn new(child: SandboxChild) -> Self {
        let pid = child.id();
        #[cfg(windows)]
        let job = child.try_clone_job().map(Arc::new);
        Self {
            pid,
            #[cfg(windows)]
            job,
            state: Arc::new(Mutex::new(SharedState::Ready(child))),
        }
    }

    /// The OS-assigned process id of the child.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    // Tolerate a poisoned mutex rather than unwrapping: if a concurrent
    // wait()/kill() panicked while holding the lock, unwrapping would propagate
    // the poison panic and kill the other caller (and, via napi, the Node
    // thread). A `PoisonedMutexGuard` derefs to the inner state just like a
    // clean guard.
    fn lock(&self) -> MutexGuard<'_, SharedState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn take_for_wait(&self) -> std::io::Result<SandboxChild> {
        let mut state = self.lock();
        match std::mem::replace(&mut *state, SharedState::Waiting { can_signal: false }) {
            SharedState::Ready(child) => {
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                {
                    *state = SharedState::Waiting {
                        can_signal: sigchld_retains_waitable_status(),
                    };
                }
                Ok(child)
            }
            // A retry cannot signal until waitid has re-established that the
            // child is waitable. It remains false through the guarded reap.
            SharedState::Uncertain(child) => Ok(child),
            previous @ (SharedState::Waiting { .. } | SharedState::Reaped) => {
                *state = previous;
                Err(std::io::Error::other(
                    "wait() has already been called on this child",
                ))
            }
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn reap_observed_child(&self, mut child: SandboxChild) -> std::io::Result<ExitStatus> {
        let mut state = self.lock();
        match child.wait() {
            Ok(status) => {
                *state = SharedState::Reaped;
                Ok(status)
            }
            Err(err) => {
                // The status may have been consumed by another process-wide
                // waiter. Retain the handle for a retry, but never signal its
                // now-unproven numeric pid.
                *state = SharedState::Uncertain(child);
                Err(err)
            }
        }
    }

    /// Wait for the child to exit, returning its status.
    ///
    /// Takes the child out of the mutex for the duration of the blocking wait so
    /// a concurrent [`kill`](Self::kill) is not blocked. Calling `wait()` while
    /// another wait is active, or after a successful wait, returns an error. A
    /// failed wait may be retried.
    pub fn wait(&self) -> std::io::Result<ExitStatus> {
        // Take the child OUT of the mutex so the blocking wait does not hold the
        // lock (kill() needs to acquire it).
        let child = self.take_for_wait()?;

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            // Block until the child exits WITHOUT reaping it (WNOWAIT): the
            // child stays a zombie, so the OS cannot reuse the pid yet and a
            // concurrent kill() signalling the pid stays safe.
            if let Err(err) = waitid_nowait(self.pid) {
                // Keep the handle for a retried wait, but fail closed for kill:
                // ECHILD can mean the OS or another waiter already reaped it.
                *self.lock() = SharedState::Uncertain(child);
                return Err(err);
            }
            // Reap and transition to Reaped while holding the lock kill()
            // signals under.
            self.reap_observed_child(child)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            // The supported Windows backend waits through a process handle,
            // which is immune to pid reuse. Other platforms use Child::wait(),
            // and all reject kill() while the handle is owned here.
            let mut child = child;
            let status = child.wait();
            let mut state = self.lock();
            match status {
                Ok(status) => {
                    *state = SharedState::Reaped;
                    Ok(status)
                }
                Err(err) => {
                    *state = SharedState::Uncertain(child);
                    Err(err)
                }
            }
        }
    }

    /// Kill the child immediately.
    ///
    /// - `wait()` not started → we still own the handle, kill it directly.
    /// - `wait()` in flight → on Linux and macOS the child is unreaped (alive
    ///   or zombie — reaping only happens under the lock held here), so
    ///   signalling the pid is safe. On Windows, raw children are terminated
    ///   through the duplicated Job Object handle, which pid reuse cannot
    ///   redirect; children without one reject this operation.
    /// - `wait()` already returned → the child has been reaped, so this is a
    ///   no-op. It must not signal a pid the OS may have reassigned.
    /// - `wait()` failed → signalling is rejected because pid ownership can no
    ///   longer be proven (on Windows the job handle keeps termination
    ///   available). The retained child handle is only available to a retried
    ///   `wait()`.
    /// - `SIGCHLD` is configured to discard child status → signalling is
    ///   rejected because the OS may auto-reap and reuse the pid.
    pub fn kill(&self) -> std::io::Result<()> {
        // Handle-based Job Object termination is immune to pid reuse, so it
        // stays safe in every state before the reap; after a successful wait
        // the tree is gone and kill remains a no-op.
        #[cfg(windows)]
        if let Some(job) = &self.job {
            let state = self.lock();
            return match &*state {
                SharedState::Reaped => Ok(()),
                _ => windows_kill_job(job),
            };
        }

        let mut state = self.lock();
        match &mut *state {
            // wait() not started → we still own the handle.
            SharedState::Ready(child) => {
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                {
                    if sigchld_retains_waitable_status() {
                        child.kill()
                    } else {
                        Err(std::io::Error::other(
                            "kill() is unsafe because SIGCHLD does not retain waitable child status",
                        ))
                    }
                }
                #[cfg(not(any(target_os = "linux", target_os = "macos")))]
                {
                    child.kill()
                }
            }
            SharedState::Waiting { can_signal } => {
                // wait() is in flight. Reaping happens only while holding this
                // lock, so the pid still names our child (alive, or a zombie
                // waitid(WNOWAIT) is holding in place). Signalling a zombie is
                // a harmless no-op.
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                {
                    if *can_signal {
                        kill_pid(self.pid)
                    } else {
                        Err(std::io::Error::other(
                            "kill() while wait() is in flight is unsafe because waitable pid ownership is not guaranteed",
                        ))
                    }
                }
                #[cfg(not(any(target_os = "linux", target_os = "macos")))]
                {
                    let _ = can_signal;
                    Err(std::io::Error::other(
                        "kill() while wait() is in flight is not supported on this platform",
                    ))
                }
            }
            SharedState::Uncertain(_) => Err(std::io::Error::other(
                "kill() after a failed wait is unsafe because pid ownership is uncertain",
            )),
            // Already reaped: the child is gone. Do not signal a pid the OS may
            // have reassigned to an unrelated process.
            SharedState::Reaped => Ok(()),
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn sigchld_retains_waitable_status() -> bool {
    let mut action = std::mem::MaybeUninit::<libc::sigaction>::uninit();
    // SAFETY: a null new action queries SIGCHLD without changing it, and action
    // is a valid out-pointer initialized by sigaction on success.
    if unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), action.as_mut_ptr()) } == -1 {
        return false;
    }
    // SAFETY: sigaction returned success and initialized action.
    let action = unsafe { action.assume_init() };
    action.sa_sigaction != libc::SIG_IGN && action.sa_flags & libc::SA_NOCLDWAIT == 0
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn kill_pid(pid: u32) -> std::io::Result<()> {
    // SAFETY: kill() with a pid and a signal takes scalar args.
    if unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Block until `pid` (a direct child) has exited, without reaping it.
///
/// Uses `waitid(P_PID, pid, WEXITED | WNOWAIT)`: on return the child is a
/// zombie whose pid the OS cannot reuse until it is actually reaped.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn waitid_nowait(pid: u32) -> std::io::Result<()> {
    loop {
        // SAFETY: siginfo_t is a plain C struct of integers; zero-initializing
        // it is a valid setup for the waitid out-pointer below.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: `info` is a valid out-pointer; P_PID/pid identify our own
        // child, and WNOWAIT leaves it waitable for the subsequent reap.
        let ret = unsafe {
            libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOWAIT,
            )
        };
        if ret == 0 {
            return Ok(());
        }
        let err = std::io::Error::last_os_error();
        if err.kind() != std::io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

impl From<SandboxChild> for SharedSandboxChild {
    fn from(child: SandboxChild) -> Self {
        SharedSandboxChild::new(child)
    }
}

/// Drain the child's piped stdout and stderr to EOF concurrently.
///
/// stderr is read on a helper thread so a child interleaving large writes on
/// both pipes cannot fill one while the parent is blocked reading the other.
#[cfg(windows)]
fn windows_read_to_end(
    stdout: Option<ChildStdout>,
    stderr: Option<ChildStderr>,
) -> std::io::Result<(Vec<u8>, Vec<u8>)> {
    use std::io::Read;

    let stderr_reader = stderr.map(|mut pipe| {
        std::thread::spawn(move || {
            let mut buffer = Vec::new();
            pipe.read_to_end(&mut buffer).map(|_| buffer)
        })
    });

    let mut stdout_buffer = Vec::new();
    if let Some(mut pipe) = stdout {
        pipe.read_to_end(&mut stdout_buffer)?;
    }
    let stderr_buffer = match stderr_reader {
        Some(handle) => match handle.join() {
            Ok(result) => result?,
            Err(_) => return Err(std::io::Error::other("stderr reader thread panicked")),
        },
        None => Vec::new(),
    };
    Ok((stdout_buffer, stderr_buffer))
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

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
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
    fn as_child_mut_exposes_the_wrapped_std_child() {
        let mut child: SandboxChild = Command::new("true").spawn().expect("spawn").into();
        let inner = child
            .as_child_mut()
            .expect("a std-backed child must expose its inner Child");
        let status = inner.wait().expect("wait");
        assert!(status.success(), "true should exit cleanly, got {status:?}");
    }

    #[test]
    fn try_into_child_returns_the_wrapped_std_child() {
        let child: SandboxChild = Command::new("true").spawn().expect("spawn").into();
        let mut inner = child
            .try_into_child()
            .expect("a std-backed child must unwrap into its inner Child");
        let status = inner.wait().expect("wait");
        assert!(status.success(), "true should exit cleanly, got {status:?}");
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
        // blocking waitid. If we race and kill first, kill() goes through the
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

    #[test]
    fn kill_on_waitid_observed_zombie_succeeds() {
        // Deterministically exercise the state where waitid(WNOWAIT) has
        // observed exit but the child has not been reaped yet.
        let child = shared(Command::new("true"));
        let owned = child.take_for_wait().expect("take child for wait");
        waitid_nowait(child.pid()).expect("observe exit without reaping");

        child
            .kill()
            .expect("signalling an observed zombie must succeed");
        let status = child
            .reap_observed_child(owned)
            .expect("reap observed child");
        assert!(status.success(), "true should exit cleanly, got {status:?}");
    }

    #[test]
    fn raw_signal_failure_is_propagated() {
        let err = kill_pid(i32::MAX as u32).expect_err("unknown pid must fail");
        assert_eq!(err.raw_os_error(), Some(libc::ESRCH));
    }

    #[test]
    fn reap_failure_disables_kill_and_allows_wait_retry() {
        let child = shared(Command::new("true"));
        let owned = child.take_for_wait().expect("take child for wait");
        waitid_nowait(child.pid()).expect("observe exit without reaping");

        // Simulate a process-wide waiter consuming this child's status before
        // SharedSandboxChild performs its guarded reap.
        let mut raw_status = 0;
        // SAFETY: raw_status is a valid out-pointer and pid is our direct child.
        let waited =
            unsafe { libc::waitpid(child.pid() as libc::pid_t, &mut raw_status, libc::WNOHANG) };
        assert_eq!(waited, child.pid() as libc::pid_t);

        let err = child
            .reap_observed_child(owned)
            .expect_err("the status was already consumed");
        assert_eq!(err.raw_os_error(), Some(libc::ECHILD));

        let kill_err = child
            .kill()
            .expect_err("an uncertain pid must never be signalled");
        assert!(
            kill_err.to_string().contains("pid ownership is uncertain"),
            "unexpected kill error: {kill_err}"
        );

        let retry_owned = child.take_for_wait().expect("start retried wait");
        let retry_kill_err = child
            .kill()
            .expect_err("a retry must not re-enable signalling");
        assert!(
            retry_kill_err
                .to_string()
                .contains("waitable pid ownership is not guaranteed"),
            "unexpected retry kill error: {retry_kill_err}"
        );
        *child.lock() = SharedState::Uncertain(retry_owned);

        let retry_err = child
            .wait()
            .expect_err("a retry still cannot recover consumed status");
        assert_eq!(retry_err.raw_os_error(), Some(libc::ECHILD));
    }

    #[test]
    fn ignored_sigchld_wait_failure_disables_kill() {
        const HELPER_ENV: &str = "GUARDRAIL_IGNORED_SIGCHLD_HELPER";

        if std::env::var_os(HELPER_ENV).is_some() {
            // This branch runs in an isolated test subprocess because signal
            // dispositions are process-global.
            // SAFETY: SIG_IGN is a valid disposition for SIGCHLD.
            let previous = unsafe { libc::signal(libc::SIGCHLD, libc::SIG_IGN) };
            assert_ne!(previous, libc::SIG_ERR, "failed to ignore SIGCHLD");

            let mut sleep = Command::new("sleep");
            sleep.arg("30");
            let waiting_child = shared(sleep);

            let ready_err = waiting_child
                .kill()
                .expect_err("ignored SIGCHLD must disable ready-state signalling");
            assert!(
                ready_err
                    .to_string()
                    .contains("SIGCHLD does not retain waitable child status"),
                "unexpected ready-state kill error: {ready_err}"
            );

            let waiter = waiting_child.clone();
            let handle = thread::spawn(move || waiter.wait());
            thread::sleep(Duration::from_millis(100));

            let in_flight_err = waiting_child
                .kill()
                .expect_err("ignored SIGCHLD must disable in-flight signalling");
            assert!(
                in_flight_err
                    .to_string()
                    .contains("waitable pid ownership is not guaranteed"),
                "unexpected in-flight kill error: {in_flight_err}"
            );
            // SAFETY: this child is deliberately sleeping and has not exited;
            // terminate it directly so the isolated helper can finish.
            let killed = unsafe { libc::kill(waiting_child.pid() as libc::pid_t, libc::SIGKILL) };
            assert_eq!(killed, 0);
            let wait_err = handle
                .join()
                .expect("waiter thread panicked")
                .expect_err("SIGCHLD ignored child has no waitable status");
            assert_eq!(wait_err.raw_os_error(), Some(libc::ECHILD));

            let child = shared(Command::new("true"));
            let err = child.wait().expect_err("auto-reaped child must not wait");
            assert_eq!(err.raw_os_error(), Some(libc::ECHILD));

            let kill_err = child
                .kill()
                .expect_err("an auto-reaped pid must never be signalled");
            assert!(
                kill_err.to_string().contains("pid ownership is uncertain"),
                "unexpected kill error: {kill_err}"
            );

            let retry_err = child
                .wait()
                .expect_err("auto-reaped status remains unavailable");
            assert_eq!(retry_err.raw_os_error(), Some(libc::ECHILD));
            return;
        }

        let status = Command::new(std::env::current_exe().expect("current test executable"))
            .args([
                "--exact",
                "process::tests::ignored_sigchld_wait_failure_disables_kill",
            ])
            .env(HELPER_ENV, "1")
            .status()
            .expect("run ignored-SIGCHLD helper");
        assert!(status.success(), "helper failed with {status:?}");
    }
}
