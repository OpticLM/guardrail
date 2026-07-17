//! Node-API bindings for the `guardrail` sandbox.
//!
//! Exposes a reusable [`Sandbox`] object plus a one-shot [`spawn`] wrapper that
//! launches a child process confined by the platform backend, returning a
//! [`SandboxChild`] handle with async `wait()` and `kill()`.
#![deny(clippy::all)]

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::process::{Command, ExitStatus};
use std::sync::Arc;

use napi::Task;
use napi::bindgen_prelude::*;
use napi_derive::napi;

use guardrail::{
    Backend, FsAccess, IpcPolicy, NetworkPolicy, PlatformBackend, SandboxConfig, SharedSandboxChild,
};

/// Network confinement level for the child: `"deny"` | `"outbound-only"` |
/// `"full"`. Mirrors `guardrail::NetworkPolicy`; the string values are the
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
/// `guardrail::IpcPolicy`.
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

#[napi(string_enum, js_name = "FsAccessKind")]
pub enum JsFsAccessKind {
    #[napi(value = "read-allow")]
    ReadAllow,
    #[napi(value = "read-deny")]
    ReadDeny,
    #[napi(value = "write-allow")]
    WriteAllow,
    #[napi(value = "write-deny")]
    WriteDeny,
    #[napi(value = "execute-allow")]
    ExecuteAllow,
    #[napi(value = "execute-deny")]
    ExecuteDeny,
}

#[napi(object, js_name = "FsAccess")]
pub struct JsFsAccess {
    /// `"read-allow"` | `"read-deny"` | `"write-allow"` | `"write-deny"` |
    /// `"execute-allow"` | `"execute-deny"`.
    pub kind: JsFsAccessKind,
    /// Path the rule covers recursively.
    pub path: String,
}

/// Sandbox policy. All fields optional; omitting everything
/// yields the maximally restrictive default (no fs, no network, strict IPC,
/// empty environment).
#[napi(object)]
#[derive(Default)]
pub struct SandboxOptions {
    /// Filesystem rules, in declaration order. Later matching rules override
    /// earlier rules for the same right. Note: `"execute-allow"` does NOT imply
    /// read — add a `"read-allow"` rule for the binary and its libraries too.
    pub fs: Option<Vec<JsFsAccess>>,
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
    /// Windows-only AppContainer cache namespace; ignored on other platforms.
    pub windows_cache_namespace: Option<String>,
}

/// One-shot sandbox policy + launch options. All fields optional; omitting
/// everything yields the maximally restrictive default.
#[napi(object)]
#[derive(Default)]
pub struct SpawnOptions {
    /// Filesystem rules, in declaration order. Later matching rules override
    /// earlier rules for the same right. Note: `"execute-allow"` does NOT imply
    /// read — add a `"read-allow"` rule for the binary and its libraries too.
    pub fs: Option<Vec<JsFsAccess>>,
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
    /// Windows-only AppContainer cache namespace; ignored on other platforms.
    pub windows_cache_namespace: Option<String>,
    /// Working directory for the child. Defaults to the parent's cwd.
    pub cwd: Option<String>,
}

/// Per-spawn launch options for a reusable [`Sandbox`].
#[napi(object)]
#[derive(Default)]
pub struct SandboxSpawnOptions {
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
}

impl From<ExitStatus> for ExitResult {
    fn from(status: ExitStatus) -> Self {
        #[cfg(unix)]
        let signal = {
            use std::os::unix::process::ExitStatusExt;
            status.signal()
        };
        #[cfg(not(unix))]
        let signal: Option<i32> = None;

        ExitResult {
            code: status.code(),
            signal,
            success: status.success(),
        }
    }
}

fn build_config(opts: SandboxOptions) -> Result<SandboxConfig> {
    let fs = opts
        .fs
        .into_iter()
        .flatten()
        .map(|g| match g.kind {
            JsFsAccessKind::ReadAllow => FsAccess::ReadAllow(g.path.into()),
            JsFsAccessKind::ReadDeny => FsAccess::ReadDeny(g.path.into()),
            JsFsAccessKind::WriteAllow => FsAccess::WriteAllow(g.path.into()),
            JsFsAccessKind::WriteDeny => FsAccess::WriteDeny(g.path.into()),
            JsFsAccessKind::ExecuteAllow => FsAccess::ExecuteAllow(g.path.into()),
            JsFsAccessKind::ExecuteDeny => FsAccess::ExecuteDeny(g.path.into()),
        })
        .collect::<Vec<_>>();

    let mut darwin_sandbox_profiles = Vec::new();
    if let Some(profiles) = opts.darwin_sandbox_profiles {
        darwin_sandbox_profiles = profiles.into_iter().map(PathBuf::from).collect();
    }

    let mut env = BTreeMap::new();
    if let Some(e) = opts.env {
        env = e.into_iter().collect();
    }

    let mut limits = guardrail::ResourceLimits::default();
    if let Some(m) = opts.memory_limit_mb {
        limits.memory_bytes = Some(u64::from(m) * 1024 * 1024);
    }
    if let Some(c) = opts.cpu_time_limit_secs {
        limits.cpu_time_secs = Some(u64::from(c));
    }
    if let Some(p) = opts.max_processes {
        limits.max_processes = Some(u64::from(p));
    }

    Ok(SandboxConfig {
        fs,
        network: opts
            .network
            .map(|n| n.into())
            .unwrap_or(NetworkPolicy::Deny),
        ipc: opts.ipc.map(|i| i.into()).unwrap_or(IpcPolicy::Strict),
        limits,
        env,
        darwin_sandbox_profiles,
        windows_cache_namespace: opts.windows_cache_namespace,
    })
}

impl From<SpawnOptions> for (SandboxOptions, Option<String>) {
    fn from(options: SpawnOptions) -> Self {
        (
            SandboxOptions {
                fs: options.fs,
                network: options.network,
                ipc: options.ipc,
                memory_limit_mb: options.memory_limit_mb,
                cpu_time_limit_secs: options.cpu_time_limit_secs,
                max_processes: options.max_processes,
                env: options.env,
                darwin_sandbox_profiles: options.darwin_sandbox_profiles,
                windows_cache_namespace: options.windows_cache_namespace,
            },
            options.cwd,
        )
    }
}

fn to_napi_err(e: guardrail::Error) -> Error {
    Error::new(Status::GenericFailure, e.to_string())
}

/// A reusable, pre-initialized sandbox.
#[napi]
pub struct Sandbox {
    backend: Arc<PlatformBackend>,
}

#[napi]
impl Sandbox {
    /// Create a sandbox and pre-initialize platform policy state off the event
    /// loop.
    #[napi(ts_return_type = "Promise<Sandbox>")]
    pub fn build(options: Option<SandboxOptions>) -> AsyncTask<BuildSandboxTask> {
        AsyncTask::new(BuildSandboxTask {
            options: options.unwrap_or_default(),
        })
    }

    /// Spawn `command` (with `args`) inside this sandbox. stdio is inherited
    /// from the parent process; every other parent file descriptor or handle
    /// is kept out of the child.
    #[napi]
    pub fn spawn(
        &self,
        command: String,
        args: Option<Vec<String>>,
        options: Option<SandboxSpawnOptions>,
    ) -> Result<SandboxChild> {
        spawn_with_backend(
            Arc::clone(&self.backend),
            command,
            args,
            options.and_then(|options| options.cwd),
        )
    }
}

pub struct BuiltSandbox {
    backend: PlatformBackend,
}

pub struct BuildSandboxTask {
    options: SandboxOptions,
}

impl Task for BuildSandboxTask {
    type Output = BuiltSandbox;
    type JsValue = Sandbox;

    fn compute(&mut self) -> Result<Self::Output> {
        let options = std::mem::take(&mut self.options);
        let config = build_config(options)?;
        let backend = PlatformBackend::new(config).map_err(to_napi_err)?;
        Ok(BuiltSandbox { backend })
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(Sandbox {
            backend: Arc::new(output.backend),
        })
    }
}

/// Probe whether this machine appears to support sandbox confinement. Throws
/// when a required kernel/OS capability cannot be probed. On Linux, Landlock
/// enforcement is verified, but the seccomp probe only checks whether the
/// kernel reports the `Trap` action; it cannot prove that an ambient sandbox
/// will permit installing the filter. Actual spawning remains authoritative
/// and fails closed, so calling this first is optional.
#[napi]
pub fn probe_support() -> Result<()> {
    PlatformBackend::probe_support().map_err(to_napi_err)
}

/// Spawn `command` (with `args`) confined by `options`. stdio is inherited from
/// the parent process; every other parent file descriptor or handle is kept
/// out of the child. Returns a handle to await or kill the child.
#[napi]
pub fn spawn(
    command: String,
    args: Option<Vec<String>>,
    options: Option<SpawnOptions>,
) -> Result<SandboxChild> {
    let (sandbox_options, cwd) = options.unwrap_or_default().into();
    let config = build_config(sandbox_options)?;
    let backend = PlatformBackend::new(config).map_err(to_napi_err)?;
    spawn_with_backend(Arc::new(backend), command, args, cwd)
}

fn spawn_with_backend(
    backend: Arc<PlatformBackend>,
    command: String,
    args: Option<Vec<String>>,
    cwd: Option<String>,
) -> Result<SandboxChild> {
    let mut cmd = Command::new(&command);
    if let Some(args) = args {
        cmd.args(args);
    }
    if let Some(cwd) = cwd {
        cmd.current_dir(cwd);
    }
    // stdio is inherited by default for std::process::Command::spawn().

    let child = backend.spawn(cmd).map_err(to_napi_err)?;

    Ok(SandboxChild {
        inner: SharedSandboxChild::new(child),
    })
}

/// Handle to a spawned, sandboxed child process.
#[napi]
pub struct SandboxChild {
    inner: SharedSandboxChild,
}

#[napi]
impl SandboxChild {
    /// OS process id of the child.
    #[napi(getter)]
    pub fn pid(&self) -> u32 {
        self.inner.pid()
    }

    /// Wait for the child to exit. Resolves with its [`ExitResult`]. Calling
    /// `wait()` more than once rejects.
    #[napi(ts_return_type = "Promise<ExitResult>")]
    pub fn wait(&self) -> AsyncTask<WaitTask> {
        AsyncTask::new(WaitTask {
            inner: self.inner.clone(),
        })
    }

    /// Kill the child immediately. Best-effort: if `wait()` is already in
    /// flight, killing falls back to an OS signal on Unix and is unsupported on
    /// Windows (see the package README).
    #[napi]
    pub fn kill(&self) -> Result<()> {
        self.inner
            .kill()
            .map_err(|e| Error::new(Status::GenericFailure, format!("failed to kill child: {e}")))
    }
}

/// libuv-threadpool task backing the async `wait()`.
pub struct WaitTask {
    inner: SharedSandboxChild,
}

impl Task for WaitTask {
    type Output = ExitResult;
    type JsValue = ExitResult;

    fn compute(&mut self) -> Result<Self::Output> {
        // The wait/kill coordination (take-out-for-wait, reaped guard, raw
        // signal fallback) lives in `SharedSandboxChild`; this just blocks until
        // the child exits and shapes the result for JS.
        let status = self.inner.wait().map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("failed to wait for child: {e}"),
            )
        })?;
        Ok(status.into())
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}
