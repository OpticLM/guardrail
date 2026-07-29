//! Node-API bindings for the `guardrail` sandbox.
//!
//! Exposes a reusable [`Sandbox`] object plus a one-shot [`spawn`] wrapper that
//! launches a child process confined by the platform backend, returning a
//! [`SandboxChild`] handle with async `wait()` and `kill()` and per-stream
//! primitives (`readStdout`/`readStderr`/`writeStdin`/`endStdin`) that the
//! hand-written `index.ts` facade composes into Node `Readable`/`Writable`
//! streams. Blocking pipe and wait calls run on dedicated OS threads so a
//! long-lived child (e.g. a persistent shell driven by an LLM tool loop)
//! never parks a libuv threadpool worker.
#![deny(clippy::all)]

use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::fd::{AsFd, BorrowedFd};
use std::path::PathBuf;
use std::process::{ChildStdin, ExitStatus};
use std::sync::Arc;
use std::sync::mpsc::{Sender, channel};

use napi::bindgen_prelude::*;
use napi::{Env, JsDeferred, Task};
use napi_derive::napi;

use guardrail::{
    Backend, FsAccess, NetworkPolicy, PlatformBackend, SandboxCommand, SandboxConfig,
    SharedSandboxChild, StdioMode, UserNamespacePolicy,
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

/// Linux-only user-namespace policy for the child: `"deny"` | `"allow"`.
/// Mirrors `guardrail::UserNamespacePolicy`. Ignored on macOS and Windows
/// (see `linuxUserNamespaces` on the options objects).
#[napi(string_enum, js_name = "UserNamespacePolicy")]
pub enum JsUserNamespacePolicy {
    #[napi(value = "deny")]
    Deny,
    #[napi(value = "allow")]
    Allow,
}

impl From<JsUserNamespacePolicy> for UserNamespacePolicy {
    fn from(p: JsUserNamespacePolicy) -> Self {
        match p {
            JsUserNamespacePolicy::Deny => UserNamespacePolicy::Deny,
            JsUserNamespacePolicy::Allow => UserNamespacePolicy::Allow,
        }
    }
}

/// Disposition of a child standard stream: `"inherit"` | `"pipe"` |
/// `"ignore"`. `"inherit"` shares the parent's stream, `"pipe"` connects a
/// pipe surfaced as a Node stream on the child handle, and `"ignore"`
/// connects the platform null device.
#[napi(string_enum, js_name = "StdioMode")]
pub enum JsStdioMode {
    #[napi(value = "inherit")]
    Inherit,
    #[napi(value = "pipe")]
    Pipe,
    #[napi(value = "ignore")]
    Ignore,
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

/// Sandbox policy. All fields optional; omitting everything yields no
/// filesystem or network access and an empty environment.
#[napi(object)]
#[derive(Default)]
pub struct SandboxOptions {
    /// Filesystem rules, in declaration order. Later matching rules override
    /// earlier rules for the same right. Note: `"execute-allow"` does NOT imply
    /// read — add a `"read-allow"` rule for the binary and its libraries too.
    pub fs: Option<Vec<JsFsAccess>>,
    /// Network confinement level; `"deny"` (default) if omitted.
    pub network: Option<JsNetworkPolicy>,
    /// Linux-only host pathname Unix socket or path-hierarchy grants,
    /// independent of `fs`. On Landlock ABI v9+ host-created pathname sockets
    /// are denied by default and these existing paths grant connection access.
    /// On older ABIs entries are ignored without being validated or opened.
    /// A granted service may pass already-open file descriptors with
    /// `SCM_RIGHTS`; their access is independent of `fs`.
    /// Ignored on macOS and Windows.
    pub linux_unix_sockets: Option<Vec<String>>,
    /// Linux-only user-namespace policy; `"deny"` (default) if omitted.
    /// Ignored on macOS and Windows. Set `"allow"` only when the child runs
    /// its own nested sandbox (Chromium/Electron, bubblewrap, rootless
    /// containers): it re-enables user-namespace creation and the mount
    /// machinery such a sandbox needs.
    pub linux_user_namespaces: Option<JsUserNamespacePolicy>,
    /// Address-space cap in megabytes. Windows: aggregate Job Object budget
    /// for the whole tree; Linux/macOS: per-process `RLIMIT_AS`, inherited by
    /// descendants but not aggregated across forks.
    pub memory_limit_mb: Option<u32>,
    /// CPU-time cap in seconds. Windows: aggregate per-job budget;
    /// Linux/macOS: per-process `RLIMIT_CPU`, not aggregated across forks.
    pub cpu_time_limit_secs: Option<u32>,
    /// Maximum number of processes. Windows: active processes in the Job
    /// Object; Linux/macOS: `RLIMIT_NPROC`, which counts all processes (on
    /// Linux, also threads) of the real user ID system-wide and is not
    /// enforced for privileged users.
    pub max_processes: Option<u32>,
    /// The ONLY environment variables the child sees (inherited env is cleared).
    /// On Windows, a bare program name resolves against this env's `PATH` only,
    /// whose non-empty entries must be absolute. Spawning e.g. `cmd` requires
    /// listing the expanded system directory, e.g. `C:\Windows\System32`.
    pub env: Option<HashMap<String, String>>,
    /// macOS-only trusted Seatbelt policy imports; ignored on other platforms.
    /// Imported `allow` rules can grant access absent from `fs` and `network`,
    /// including filesystem paths not listed in `fs`. Review profiles and their
    /// transitive imports, and keep them outside child-writable paths.
    pub darwin_sandbox_profiles: Option<Vec<String>>,
    /// Windows-only AppContainer cache namespace; ignored on other platforms.
    pub windows_cache_namespace: Option<String>,
    /// Windows-only override for the directory holding per-namespace ACL
    /// manifests (defaults to `%LOCALAPPDATA%\guardrail`); ignored on other
    /// platforms.
    pub windows_manifest_dir: Option<String>,
    /// Windows-only startup ACL verification for an unchanged policy:
    /// `"none"` | `"deny-roots"` (default) | `"all-roots"`; ignored on other
    /// platforms.
    pub windows_acl_verification: Option<String>,
}

/// One-shot sandbox policy + launch options. All fields optional; omitting
/// everything yields no filesystem or network access and an empty environment.
#[napi(object)]
#[derive(Default)]
pub struct SpawnOptions {
    /// Filesystem rules, in declaration order. Later matching rules override
    /// earlier rules for the same right. Note: `"execute-allow"` does NOT imply
    /// read — add a `"read-allow"` rule for the binary and its libraries too.
    pub fs: Option<Vec<JsFsAccess>>,
    /// Network confinement level; `"deny"` (default) if omitted.
    pub network: Option<JsNetworkPolicy>,
    /// Linux-only host pathname Unix socket or path-hierarchy grants,
    /// independent of `fs`. Enforced on Landlock ABI v9+; ignored without
    /// validation on older ABIs and ignored on macOS and Windows. A granted
    /// service may pass already-open file descriptors with `SCM_RIGHTS`;
    /// their access is independent of `fs`.
    pub linux_unix_sockets: Option<Vec<String>>,
    /// Linux-only user-namespace policy; `"deny"` (default) if omitted.
    /// Ignored on macOS and Windows. Set `"allow"` only when the child runs
    /// its own nested sandbox (Chromium/Electron, bubblewrap, rootless
    /// containers): it re-enables user-namespace creation and the mount
    /// machinery such a sandbox needs.
    pub linux_user_namespaces: Option<JsUserNamespacePolicy>,
    /// Address-space cap in megabytes. Windows: aggregate Job Object budget
    /// for the whole tree; Linux/macOS: per-process `RLIMIT_AS`, inherited by
    /// descendants but not aggregated across forks.
    pub memory_limit_mb: Option<u32>,
    /// CPU-time cap in seconds. Windows: aggregate per-job budget;
    /// Linux/macOS: per-process `RLIMIT_CPU`, not aggregated across forks.
    pub cpu_time_limit_secs: Option<u32>,
    /// Maximum number of processes. Windows: active processes in the Job
    /// Object; Linux/macOS: `RLIMIT_NPROC`, which counts all processes (on
    /// Linux, also threads) of the real user ID system-wide and is not
    /// enforced for privileged users.
    pub max_processes: Option<u32>,
    /// The ONLY environment variables the child sees (inherited env is cleared).
    /// On Windows, a bare program name resolves against this env's `PATH` only,
    /// whose non-empty entries must be absolute. Spawning e.g. `cmd` requires
    /// listing the expanded system directory, e.g. `C:\Windows\System32`.
    pub env: Option<HashMap<String, String>>,
    /// macOS-only trusted Seatbelt policy imports; ignored on other platforms.
    /// Imported `allow` rules can grant access absent from `fs` and `network`,
    /// including filesystem paths not listed in `fs`. Review profiles and their
    /// transitive imports, and keep them outside child-writable paths.
    pub darwin_sandbox_profiles: Option<Vec<String>>,
    /// Windows-only AppContainer cache namespace; ignored on other platforms.
    pub windows_cache_namespace: Option<String>,
    /// Windows-only override for the directory holding per-namespace ACL
    /// manifests (defaults to `%LOCALAPPDATA%\guardrail`); ignored on other
    /// platforms.
    pub windows_manifest_dir: Option<String>,
    /// Windows-only startup ACL verification for an unchanged policy:
    /// `"none"` | `"deny-roots"` (default) | `"all-roots"`; ignored on other
    /// platforms.
    pub windows_acl_verification: Option<String>,
    /// Working directory for the child. Defaults to the parent's cwd.
    pub cwd: Option<String>,
    /// stdin disposition; `"inherit"` (default) shares the parent's stream,
    /// `"pipe"` exposes a `Writable` as `child.stdin`, `"ignore"` connects
    /// the null device.
    pub stdin: Option<JsStdioMode>,
    /// stdout disposition; `"inherit"` (default) shares the parent's stream,
    /// `"pipe"` exposes a `Readable` as `child.stdout`, `"ignore"` connects
    /// the null device.
    pub stdout: Option<JsStdioMode>,
    /// stderr disposition; same values as `stdout` (`child.stderr`).
    pub stderr: Option<JsStdioMode>,
}

/// Per-spawn launch options for a reusable [`Sandbox`].
#[napi(object)]
#[derive(Default)]
pub struct SandboxSpawnOptions {
    /// Working directory for the child. Defaults to the parent's cwd.
    pub cwd: Option<String>,
    /// stdin disposition; `"inherit"` (default) shares the parent's stream,
    /// `"pipe"` exposes a `Writable` as `child.stdin`, `"ignore"` connects
    /// the null device.
    pub stdin: Option<JsStdioMode>,
    /// stdout disposition; `"inherit"` (default) shares the parent's stream,
    /// `"pipe"` exposes a `Readable` as `child.stdout`, `"ignore"` connects
    /// the null device.
    pub stdout: Option<JsStdioMode>,
    /// stderr disposition; same values as `stdout` (`child.stderr`).
    pub stderr: Option<JsStdioMode>,
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
        limits,
        env,
        linux_unix_sockets: opts
            .linux_unix_sockets
            .unwrap_or_default()
            .into_iter()
            .map(PathBuf::from)
            .collect(),
        linux_user_namespaces: opts
            .linux_user_namespaces
            .map(|u| u.into())
            .unwrap_or(UserNamespacePolicy::Deny),
        darwin_sandbox_profiles,
        windows_cache_namespace: opts.windows_cache_namespace,
        windows_manifest_dir: opts.windows_manifest_dir.map(PathBuf::from),
        windows_acl_verification: match opts.windows_acl_verification.as_deref() {
            None | Some("deny-roots") => guardrail::WindowsAclVerification::DenyRoots,
            Some("none") => guardrail::WindowsAclVerification::None,
            Some("all-roots") => guardrail::WindowsAclVerification::AllRoots,
            Some(other) => {
                return Err(Error::new(
                    Status::InvalidArg,
                    format!(
                        "invalid windowsAclVerification {other:?}: expected \"none\", \"deny-roots\", or \"all-roots\""
                    ),
                ));
            }
        },
    })
}

impl From<SpawnOptions> for (SandboxOptions, SandboxSpawnOptions) {
    fn from(options: SpawnOptions) -> Self {
        (
            SandboxOptions {
                fs: options.fs,
                network: options.network,
                linux_unix_sockets: options.linux_unix_sockets,
                linux_user_namespaces: options.linux_user_namespaces,
                memory_limit_mb: options.memory_limit_mb,
                cpu_time_limit_secs: options.cpu_time_limit_secs,
                max_processes: options.max_processes,
                env: options.env,
                darwin_sandbox_profiles: options.darwin_sandbox_profiles,
                windows_cache_namespace: options.windows_cache_namespace,
                windows_manifest_dir: options.windows_manifest_dir,
                windows_acl_verification: options.windows_acl_verification,
            },
            SandboxSpawnOptions {
                cwd: options.cwd,
                stdin: options.stdin,
                stdout: options.stdout,
                stderr: options.stderr,
            },
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

    /// Spawn `command` (with `args`) inside this sandbox. Each standard stream
    /// follows its configured disposition — inherited from the parent process
    /// by default; every other parent file descriptor or handle is kept out of
    /// the child.
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
            options.unwrap_or_default(),
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
/// and fails closed, so calling this first is optional. Policy-specific checks,
/// such as the Landlock ABI v4 requirement for outbound-only networking, run
/// when `Sandbox.build()` or one-shot `spawn()` constructs the backend.
#[napi]
pub fn probe_support() -> Result<()> {
    PlatformBackend::probe_support().map_err(to_napi_err)
}

/// Windows only: whether every `guardrail-host-setup` grant is present — the
/// null-device write grant, the mount-point-manager access grant (both reset
/// on reboot), and the system ancestor traverse grants (persistent). When
/// `false`, sandboxes still spawn but `> nul` redirection, path
/// canonicalization (git/jj cwd resolution), or ancestor stats degrade; run
/// `guardrail-host-setup` elevated to apply. Throws on non-Windows platforms.
#[napi]
pub fn windows_host_setup_configured() -> Result<bool> {
    #[cfg(windows)]
    {
        let nul = guardrail::null_device_write_configured()
            .map_err(|err| Error::new(Status::GenericFailure, err.to_string()))?;
        let mountmgr = guardrail::mount_point_manager_access_configured()
            .map_err(|err| Error::new(Status::GenericFailure, err.to_string()))?;
        let traverse = guardrail::system_traverse_grants_configured()
            .map_err(|err| Error::new(Status::GenericFailure, err.to_string()))?;
        Ok(nul && mountmgr && traverse)
    }
    #[cfg(not(windows))]
    Err(Error::new(
        Status::GenericFailure,
        "windowsHostSetupConfigured is Windows-only",
    ))
}

/// Windows only: retire a persistent cache namespace — remove every guardrail
/// ACE its manifest records, delete its AppContainer profile, and delete its
/// manifest directory. `namespace`/`manifestDir` mirror the
/// `windowsCacheNamespace`/`windowsManifestDir` options. Fails while the
/// namespace is active in any process. Throws on non-Windows platforms.
#[napi]
pub fn cleanup_windows_namespace(
    namespace: Option<String>,
    manifest_dir: Option<String>,
) -> Result<()> {
    #[cfg(windows)]
    {
        guardrail::cleanup_windows_namespace(
            namespace.as_deref(),
            manifest_dir.as_deref().map(std::path::Path::new),
        )
        .map_err(|err| Error::new(Status::GenericFailure, err.to_string()))
    }
    #[cfg(not(windows))]
    {
        let _ = (namespace, manifest_dir);
        Err(Error::new(
            Status::GenericFailure,
            "cleanupWindowsNamespace is Windows-only",
        ))
    }
}

/// Spawn `command` (with `args`) confined by `options`. Each standard stream
/// follows its configured disposition — inherited from the parent process by
/// default; every other parent file descriptor or handle is kept out of the
/// child. Returns a handle to await or kill the child.
#[napi]
pub fn spawn(
    command: String,
    args: Option<Vec<String>>,
    options: Option<SpawnOptions>,
) -> Result<SandboxChild> {
    let (sandbox_options, launch) = options.unwrap_or_default().into();
    let config = build_config(sandbox_options)?;
    let backend = PlatformBackend::new(config).map_err(to_napi_err)?;
    spawn_with_backend(Arc::new(backend), command, args, launch)
}

fn spawn_with_backend(
    backend: Arc<PlatformBackend>,
    command: String,
    args: Option<Vec<String>>,
    launch: SandboxSpawnOptions,
) -> Result<SandboxChild> {
    let mut cmd = SandboxCommand::new(command);
    if let Some(args) = args {
        cmd.args = args.into_iter().map(Into::into).collect();
    }
    if let Some(cwd) = launch.cwd {
        cmd.current_dir = Some(cwd.into());
    }
    match launch.stdin.unwrap_or(JsStdioMode::Inherit) {
        JsStdioMode::Pipe => cmd.stdin = StdioMode::Piped,
        JsStdioMode::Ignore => cmd.stdin = StdioMode::Null,
        JsStdioMode::Inherit => {}
    }
    match launch.stdout.unwrap_or(JsStdioMode::Inherit) {
        JsStdioMode::Pipe => cmd.stdout = StdioMode::Piped,
        JsStdioMode::Ignore => cmd.stdout = StdioMode::Null,
        JsStdioMode::Inherit => {}
    }
    match launch.stderr.unwrap_or(JsStdioMode::Inherit) {
        JsStdioMode::Pipe => cmd.stderr = StdioMode::Piped,
        JsStdioMode::Ignore => cmd.stderr = StdioMode::Null,
        JsStdioMode::Inherit => {}
    }
    #[cfg(unix)]
    materialize_inherited_stdio(&mut cmd)?;

    let mut child = backend.spawn(cmd).map_err(to_napi_err)?;
    let stdin = child.take_stdin().map(StdinWriter::spawn);
    let stdout = child.take_stdout().map(PipeReader::spawn);
    let stderr = child.take_stderr().map(PipeReader::spawn);

    Ok(SandboxChild {
        inner: SharedSandboxChild::new(child),
        stdin,
        stdout,
        stderr,
    })
}

#[cfg(unix)]
fn materialize_inherited_stdio(command: &mut SandboxCommand) -> Result<()> {
    // Node/libuv may keep FD_CLOEXEC on descriptors 0-2. Explicit file modes
    // make Command dup the cloned descriptors onto the child's stdio slots.
    if matches!(command.stdin, StdioMode::Inherit) {
        command.stdin = duplicate_stdio(std::io::stdin().as_fd(), "stdin")?;
    }
    if matches!(command.stdout, StdioMode::Inherit) {
        command.stdout = duplicate_stdio(std::io::stdout().as_fd(), "stdout")?;
    }
    if matches!(command.stderr, StdioMode::Inherit) {
        command.stderr = duplicate_stdio(std::io::stderr().as_fd(), "stderr")?;
    }
    Ok(())
}

#[cfg(unix)]
fn duplicate_stdio(fd: BorrowedFd<'_>, name: &str) -> Result<StdioMode> {
    let fd = fd.try_clone_to_owned().map_err(|err| {
        Error::new(
            Status::GenericFailure,
            format!("failed to inherit {name}: {err}"),
        )
    })?;
    Ok(StdioMode::File(fd.into()))
}

/// Handle to a spawned, sandboxed child process.
///
/// The methods here are the raw binding surface; the package's hand-written
/// `index.ts` wraps them into the public class whose `stdin`/`stdout`/`stderr`
/// are real Node streams.
#[napi]
pub struct SandboxChild {
    inner: SharedSandboxChild,
    stdin: Option<StdinWriter>,
    stdout: Option<PipeReader>,
    stderr: Option<PipeReader>,
}

#[napi]
impl SandboxChild {
    /// OS process id of the child.
    #[napi(getter)]
    pub fn pid(&self) -> u32 {
        self.inner.pid()
    }

    /// Wait for the child to exit on a dedicated thread, resolving with its
    /// [`ExitResult`]. Calling `wait()` while another wait is active, or
    /// after one succeeds, rejects; the `index.ts` facade memoizes the
    /// promise so JS callers can await it any number of times.
    #[napi(ts_return_type = "Promise<ExitResult>")]
    pub fn wait<'env>(&self, env: &'env Env) -> Result<Object<'env>> {
        let (deferred, promise) = env.create_deferred::<ExitResult, ExitResolver>()?;
        let inner = self.inner.clone();
        std::thread::spawn(move || match inner.wait() {
            Ok(status) => deferred.resolve(Box::new(move |_| Ok(ExitResult::from(status)))),
            Err(err) => deferred.reject(Error::new(
                Status::GenericFailure,
                format!("failed to wait for child: {err}"),
            )),
        });
        Ok(promise)
    }

    /// Kill the child immediately: SIGKILL on Unix, Job Object termination on
    /// Windows. Safe at any time — before, during, or after `wait()` (a no-op
    /// once the child has been reaped).
    #[napi]
    pub fn kill(&self) -> Result<()> {
        self.inner
            .kill()
            .map_err(|e| Error::new(Status::GenericFailure, format!("failed to kill child: {e}")))
    }

    /// Resolve with the next stdout chunk, or `null` at end-of-stream.
    /// Primitive consumed by the `index.ts` `Readable`; issue one call at a
    /// time and stop after `null`.
    #[napi(ts_return_type = "Promise<Buffer | null>")]
    pub fn read_stdout<'env>(&self, env: &'env Env) -> Result<Object<'env>> {
        read_chunk(env, self.stdout.as_ref())
    }

    /// Resolve with the next stderr chunk, or `null` at end-of-stream. See
    /// [`read_stdout`](Self::read_stdout).
    #[napi(ts_return_type = "Promise<Buffer | null>")]
    pub fn read_stderr<'env>(&self, env: &'env Env) -> Result<Object<'env>> {
        read_chunk(env, self.stderr.as_ref())
    }

    /// Write `data` to the child's piped stdin, resolving once the OS
    /// accepted the bytes — the backpressure signal the `index.ts` `Writable`
    /// propagates. Rejects when stdin was not spawned with `"pipe"` or has
    /// already been ended.
    #[napi(ts_return_type = "Promise<void>")]
    pub fn write_stdin<'env>(&self, env: &'env Env, data: Buffer) -> Result<Object<'env>> {
        let (deferred, promise) = env.create_deferred::<(), UnitResolver>()?;
        match &self.stdin {
            Some(writer) => writer.write(data.to_vec(), deferred),
            None => deferred.reject(Error::new(
                Status::GenericFailure,
                "stdin is not piped; spawn with stdin: 'pipe'",
            )),
        }
        Ok(promise)
    }

    /// Close the child's piped stdin once queued writes have flushed,
    /// delivering EOF to the child. Idempotent; a no-op when stdin was never
    /// piped.
    #[napi(ts_return_type = "Promise<void>")]
    pub fn end_stdin<'env>(&self, env: &'env Env) -> Result<Object<'env>> {
        let (deferred, promise) = env.create_deferred::<(), UnitResolver>()?;
        match &self.stdin {
            Some(writer) => writer.end(deferred),
            None => deferred.resolve(Box::new(|_| Ok(()))),
        }
        Ok(promise)
    }
}

// Boxed resolver aliases: JsDeferred is generic over its resolver closure, so
// channel and helper signatures need a nameable type.
type ChunkResolver = Box<dyn FnOnce(Env) -> Result<Option<Buffer>> + Send>;
type ChunkDeferred = JsDeferred<Option<Buffer>, ChunkResolver>;
type UnitResolver = Box<dyn FnOnce(Env) -> Result<()> + Send>;
type UnitDeferred = JsDeferred<(), UnitResolver>;
type ExitResolver = Box<dyn FnOnce(Env) -> Result<ExitResult> + Send>;

fn io_error(context: &str, err: std::io::Error) -> Error {
    Error::new(Status::GenericFailure, format!("{context}: {err}"))
}

/// Demand-driven reader for one piped output stream.
///
/// A dedicated OS thread owns the pipe end and blocks in `read` only while a
/// JS read is pending, so an idle child costs one parked thread — never a
/// libuv threadpool worker, whose small process-wide pool (4 by default) must
/// stay available to Node. Reading only on demand also bounds buffering at
/// one chunk plus the OS pipe capacity: a child that outruns its consumer
/// blocks on a full pipe instead of growing host memory.
struct PipeReader {
    demand: Sender<ChunkDeferred>,
}

impl PipeReader {
    fn spawn(pipe: impl Read + Send + 'static) -> Self {
        let (demand, requests) = channel::<ChunkDeferred>();
        std::thread::spawn(move || {
            let mut pipe = Some(pipe);
            let mut buffer = vec![0u8; 64 * 1024];
            for deferred in requests {
                let Some(open) = pipe.as_mut() else {
                    // End-of-stream is sticky once EOF or a read error closed
                    // the pipe.
                    deferred.resolve(Box::new(|_| Ok(None)));
                    continue;
                };
                match open.read(&mut buffer) {
                    Ok(0) => {
                        pipe = None;
                        deferred.resolve(Box::new(|_| Ok(None)));
                    }
                    Ok(read) => {
                        let chunk = buffer.get(..read).unwrap_or_default().to_vec();
                        deferred.resolve(Box::new(move |_| Ok(Some(Buffer::from(chunk)))));
                    }
                    Err(err) => {
                        pipe = None;
                        deferred.reject(io_error("failed to read piped output", err));
                    }
                }
            }
        });
        Self { demand }
    }
}

fn read_chunk<'env>(env: &'env Env, reader: Option<&PipeReader>) -> Result<Object<'env>> {
    let (deferred, promise) = env.create_deferred::<Option<Buffer>, ChunkResolver>()?;
    match reader {
        Some(reader) => {
            // The reader thread outlives its sender, so a failed send can only
            // mean it is gone; answer end-of-stream rather than wedging the
            // pending promise.
            if let Err(returned) = reader.demand.send(deferred) {
                returned.0.resolve(Box::new(|_| Ok(None)));
            }
        }
        // Stream not piped: permanent end-of-stream instead of an error, so
        // wrapper misuse cannot wedge a Readable.
        None => deferred.resolve(Box::new(|_| Ok(None))),
    }
    Ok(promise)
}

/// Order-preserving writer for the child's piped stdin.
///
/// A dedicated OS thread owns the write end: a full pipe (the child stopped
/// reading) blocks that thread rather than the JS thread or a libuv worker,
/// and each write's promise resolves only after the OS accepted the bytes.
struct StdinWriter {
    requests: Sender<StdinRequest>,
}

enum StdinRequest {
    Write(Vec<u8>, UnitDeferred),
    End(UnitDeferred),
}

impl StdinWriter {
    fn spawn(pipe: ChildStdin) -> Self {
        let (requests, incoming) = channel::<StdinRequest>();
        std::thread::spawn(move || {
            let mut pipe = Some(pipe);
            for request in incoming {
                match request {
                    StdinRequest::Write(data, deferred) => match pipe.as_mut() {
                        Some(open) => match open.write_all(&data) {
                            Ok(()) => deferred.resolve(Box::new(|_| Ok(()))),
                            Err(err) => {
                                // A broken pipe (the child exited) stays
                                // broken; drop our end so the child side sees
                                // EOF either way.
                                pipe = None;
                                deferred.reject(io_error("failed to write to stdin", err));
                            }
                        },
                        None => deferred.reject(Error::new(
                            Status::GenericFailure,
                            "stdin has already been ended",
                        )),
                    },
                    StdinRequest::End(deferred) => {
                        // Requests are handled in arrival order, so queued
                        // writes have flushed; dropping the write end delivers
                        // EOF.
                        pipe = None;
                        deferred.resolve(Box::new(|_| Ok(())));
                    }
                }
            }
        });
        Self { requests }
    }

    fn write(&self, data: Vec<u8>, deferred: UnitDeferred) {
        if let Err(returned) = self.requests.send(StdinRequest::Write(data, deferred))
            && let StdinRequest::Write(_, deferred) = returned.0
        {
            deferred.reject(Error::new(
                Status::GenericFailure,
                "stdin writer is no longer running",
            ));
        }
    }

    fn end(&self, deferred: UnitDeferred) {
        if let Err(returned) = self.requests.send(StdinRequest::End(deferred))
            && let StdinRequest::End(deferred) = returned.0
        {
            deferred.resolve(Box::new(|_| Ok(())));
        }
    }
}
