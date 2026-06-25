//! Node-API bindings for the `guardrail` sandbox.
//!
//! Exposes a single [`spawn`] function that launches a child process confined
//! by the platform backend, returning a [`SandboxChild`] handle with async
//! `wait()` and `kill()`. Policy is supplied as a plain options object that
//! mirrors `guardrail_core::SandboxBuilder`.
#![deny(clippy::all)]

use std::collections::HashMap;
use std::process::{Command, ExitStatus};
use std::sync::{Arc, Mutex};

use napi::Task;
use napi::bindgen_prelude::*;
use napi_derive::napi;

use guardrail_core::{
    IpcPolicy, NetworkPolicy, SandboxBuilder, SandboxChild as CoreChild, SandboxConfig,
    ViolationKind,
};

// Compile-time backend + diagnostics selection: each published binary targets
// exactly one OS, so the correct backend is chosen at build time.
#[cfg(target_os = "linux")]
use guardrail_linux::{LinuxBackend as PlatformBackend, diagnostics::explain};
#[cfg(target_os = "macos")]
use guardrail_macos::{MacosBackend as PlatformBackend, diagnostics::explain};
#[cfg(target_os = "windows")]
use guardrail_windows::{WindowsBackend as PlatformBackend, diagnostics::explain};

/// Network confinement level for the child: `"deny"` | `"outbound-only"` |
/// `"full"`. Mirrors `guardrail_core::NetworkPolicy`; the string values are the
/// ones typed by the JS caller.
#[napi(string_enum, js_name = "NetworkPolicy")]
pub enum JsNetworkPolicy {
    #[napi(value = "deny")]
    Deny,
    #[napi(value = "outbound-only")]
    OutboundOnly,
    #[napi(value = "full")]
    Full,
}

impl From<JsNetworkPolicy> for NetworkPolicy {
    fn from(p: JsNetworkPolicy) -> Self {
        match p {
            JsNetworkPolicy::Deny => NetworkPolicy::Deny,
            JsNetworkPolicy::OutboundOnly => NetworkPolicy::OutboundOnly,
            JsNetworkPolicy::Full => NetworkPolicy::Full,
        }
    }
}

/// IPC confinement level for the child: `"strict"` | `"relaxed"`. Mirrors
/// `guardrail_core::IpcPolicy`.
#[napi(string_enum, js_name = "IpcPolicy")]
pub enum JsIpcPolicy {
    #[napi(value = "strict")]
    Strict,
    #[napi(value = "relaxed")]
    Relaxed,
}

impl From<JsIpcPolicy> for IpcPolicy {
    fn from(p: JsIpcPolicy) -> Self {
        match p {
            JsIpcPolicy::Strict => IpcPolicy::Strict,
            JsIpcPolicy::Relaxed => IpcPolicy::Relaxed,
        }
    }
}

/// The category of a suspected policy violation: `"seccomp"` | `"resource-limit"`
/// | `"filesystem"` | `"unknown"`. Mirrors `guardrail_core::ViolationKind`.
#[napi(string_enum, js_name = "ViolationKind")]
pub enum JsViolationKind {
    #[napi(value = "seccomp")]
    Seccomp,
    #[napi(value = "resource-limit")]
    ResourceLimit,
    #[napi(value = "filesystem")]
    Filesystem,
    #[napi(value = "unknown")]
    Unknown,
}

impl From<ViolationKind> for JsViolationKind {
    // `ViolationKind` is `#[non_exhaustive]`: any future core variant maps to
    // `Unknown` so a new kind does not break the JS surface.
    fn from(k: ViolationKind) -> Self {
        match k {
            ViolationKind::Seccomp => JsViolationKind::Seccomp,
            ViolationKind::ResourceLimit => JsViolationKind::ResourceLimit,
            ViolationKind::Filesystem => JsViolationKind::Filesystem,
            _ => JsViolationKind::Unknown,
        }
    }
}

/// Sandbox policy + launch options. All fields optional; omitting everything
/// yields the maximally restrictive default (no fs, no network, strict IPC,
/// empty environment).
#[napi(object)]
#[derive(Default)]
pub struct SpawnOptions {
    /// Paths granted read access (recursive).
    pub read_paths: Option<Vec<String>>,
    /// Paths granted read+write access (recursive).
    pub write_paths: Option<Vec<String>>,
    /// Paths granted execute access (recursive). Note: execute does NOT imply
    /// read; grant `readPaths` for the binary and its libraries too.
    pub execute_paths: Option<Vec<String>>,
    /// Network confinement level; `"deny"` (default) if omitted.
    pub network: Option<JsNetworkPolicy>,
    /// IPC confinement level; `"strict"` (default) if omitted.
    pub ipc: Option<JsIpcPolicy>,
    /// Address-space cap in megabytes.
    pub memory_limit_mb: Option<u32>,
    /// CPU-time cap in seconds.
    pub cpu_time_limit_secs: Option<u32>,
    /// Maximum number of processes/threads.
    pub max_processes: Option<u32>,
    /// The ONLY environment variables the child sees (inherited env is cleared).
    pub env: Option<HashMap<String, String>>,
    /// macOS-only Seatbelt `.sb` profile paths; ignored on other platforms.
    pub darwin_sandbox_profiles: Option<Vec<String>>,
    /// Working directory for the child. Defaults to the parent's cwd.
    pub cwd: Option<String>,
}

/// The result of awaiting a child's exit.
#[napi(object)]
pub struct ExitResult {
    /// Exit code, or `null` if the process was terminated by a signal (Unix).
    pub code: Option<i32>,
    /// Terminating signal number (Unix only); `null` otherwise.
    pub signal: Option<i32>,
    /// `true` iff the process exited cleanly with code 0.
    pub success: bool,
    /// Best-effort diagnostic when the run failed; `null` on success or when the
    /// failure could not be attributed to a policy.
    #[napi(ts_type = "Violation")]
    pub violation: Option<JsViolation>,
}

/// A heuristic explanation of a suspected policy violation.
#[napi(object, js_name = "Violation")]
pub struct JsViolation {
    /// The suspected category.
    pub kind: JsViolationKind,
    /// One-line human summary.
    pub summary: String,
    /// Copy-pasteable next steps (which option to add to loosen the policy).
    pub suggestions: Vec<String>,
}

fn build_config(opts: SpawnOptions) -> Result<SandboxConfig> {
    let mut b = SandboxBuilder::new();
    for p in opts.read_paths.into_iter().flatten() {
        b = b.allow_read(p);
    }
    for p in opts.write_paths.into_iter().flatten() {
        b = b.allow_write(p);
    }
    for p in opts.execute_paths.into_iter().flatten() {
        b = b.allow_execute(p);
    }
    if let Some(n) = opts.network {
        b = b.network(n.into());
    }
    if let Some(i) = opts.ipc {
        b = b.ipc(i.into());
    }
    if let Some(m) = opts.memory_limit_mb {
        b = b.memory_limit_mb(u64::from(m));
    }
    if let Some(c) = opts.cpu_time_limit_secs {
        b = b.cpu_time_limit_secs(u64::from(c));
    }
    if let Some(p) = opts.max_processes {
        b = b.max_processes(u64::from(p));
    }
    for p in opts.darwin_sandbox_profiles.into_iter().flatten() {
        b = b.darwin_sandbox_profile(p);
    }
    if let Some(env) = opts.env {
        b = b.envs(env);
    }
    Ok(b.build())
}

fn to_napi_err(e: guardrail_core::Error) -> Error {
    Error::new(Status::GenericFailure, e.to_string())
}

fn build_exit_result(config: &SandboxConfig, status: ExitStatus) -> ExitResult {
    #[cfg(unix)]
    let signal = {
        use std::os::unix::process::ExitStatusExt;
        status.signal()
    };
    #[cfg(not(unix))]
    let signal: Option<i32> = None;

    let violation = explain(config, status).map(|v| JsViolation {
        kind: violation_kind_str(v.kind).to_string(),
        summary: v.summary,
        suggestions: v.suggestions,
    });

    ExitResult {
        code: status.code(),
        signal,
        success: status.success(),
        violation,
    }
}

/// Spawn `command` (with `args`) confined by `options`. stdio is inherited from
/// the parent process. Returns a handle to await or kill the child.
#[napi]
pub fn spawn(
    command: String,
    args: Option<Vec<String>>,
    options: Option<SpawnOptions>,
) -> Result<SandboxChild> {
    let options = options.unwrap_or_default();
    let cwd = options.cwd.clone();
    let config = build_config(options)?;

    let mut cmd = Command::new(&command);
    if let Some(args) = args {
        cmd.args(args);
    }
    if let Some(cwd) = cwd {
        cmd.current_dir(cwd);
    }
    // stdio is inherited by default for std::process::Command::spawn().

    let backend = PlatformBackend::new();
    let child = config.spawn_with(&backend, cmd).map_err(to_napi_err)?;
    let pid = child.id();

    Ok(SandboxChild {
        pid,
        inner: Arc::new(Mutex::new(Some(child))),
        config: Arc::new(config),
    })
}

/// Handle to a spawned, sandboxed child process.
#[napi]
pub struct SandboxChild {
    pid: u32,
    // `Option` so `wait()` can take ownership of the child for the duration of
    // the blocking wait without holding the mutex (which would deadlock kill()).
    inner: Arc<Mutex<Option<CoreChild>>>,
    config: Arc<SandboxConfig>,
}

#[napi]
impl SandboxChild {
    /// OS process id of the child.
    #[napi(getter)]
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Wait for the child to exit. Resolves with its [`ExitResult`]. Calling
    /// `wait()` more than once rejects.
    #[napi(ts_return_type = "Promise<ExitResult>")]
    pub fn wait(&self) -> AsyncTask<WaitTask> {
        AsyncTask::new(WaitTask {
            inner: self.inner.clone(),
            config: self.config.clone(),
        })
    }

    /// Kill the child immediately. Best-effort: if `wait()` is already in
    /// flight, killing falls back to an OS signal on Unix and is unsupported on
    /// Windows (see the package README).
    #[napi]
    pub fn kill(&self) -> Result<()> {
        let mut guard = self.inner.lock().unwrap();
        match guard.as_mut() {
            Some(child) => child.kill().map_err(|e| {
                Error::new(Status::GenericFailure, format!("failed to kill child: {e}"))
            }),
            None => {
                // wait() owns the child and is blocking on it.
                #[cfg(unix)]
                {
                    // SAFETY: kill() with a pid and a signal takes scalar args.
                    // The child is still alive (wait has not returned), so the
                    // pid has not been reaped/reused yet.
                    unsafe {
                        libc::kill(self.pid as libc::pid_t, libc::SIGKILL);
                    }
                    Ok(())
                }
                #[cfg(not(unix))]
                {
                    Err(Error::new(
                        Status::GenericFailure,
                        "kill() after wait() has started is not supported on this platform",
                    ))
                }
            }
        }
    }
}

/// libuv-threadpool task backing the async `wait()`.
pub struct WaitTask {
    inner: Arc<Mutex<Option<CoreChild>>>,
    config: Arc<SandboxConfig>,
}

impl Task for WaitTask {
    type Output = ExitResult;
    type JsValue = ExitResult;

    fn compute(&mut self) -> Result<Self::Output> {
        // Take the child OUT of the mutex so the blocking wait does not hold the
        // lock (kill() needs to acquire it). If it is already gone, wait() was
        // called twice.
        let mut child = {
            let mut guard = self.inner.lock().unwrap();
            guard.take().ok_or_else(|| {
                Error::new(
                    Status::GenericFailure,
                    "wait() has already been called on this child",
                )
            })?
        };
        let status = child.wait().map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("failed to wait for child: {e}"),
            )
        })?;
        Ok(build_exit_result(&self.config, status))
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}
