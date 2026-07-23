#![cfg(windows)]

//! Standard-stream regression coverage for issue #21: the backend must honor
//! the command's stdio modes while keeping every unrelated inheritable handle
//! out of the child.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use guardrail_core::{
    Backend, FsAccess, NetworkPolicy, ResourceLimits, SandboxCommand, SandboxConfig, StdioMode,
    UserNamespacePolicy,
};
use guardrail_windows::WindowsBackend;
use windows_sys::Win32::Foundation::{
    HANDLE_FLAG_INHERIT, STATUS_INVALID_HANDLE, SetHandleInformation,
};

static COUNTER: AtomicU64 = AtomicU64::new(1);

fn probe() -> SandboxCommand {
    SandboxCommand::new(env!("CARGO_BIN_EXE_guardrail-windows-probe"))
}

fn probe_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_guardrail-windows-probe"))
        .parent()
        .expect("probe binary has a parent directory")
        .to_path_buf()
}

fn spawn_child(config: &SandboxConfig, command: SandboxCommand) -> guardrail_core::SandboxChild {
    WindowsBackend::new(config.clone())
        .expect("backend")
        .spawn(command)
        .expect("spawn")
}

#[test]
fn default_inherited_stdio_launches_and_exits_cleanly() {
    let config = config_with_probe_grant();
    let mut command = probe();
    command.args = vec!["echo-stdio".into()];

    let mut child = spawn_child(&config, command);
    let status = child.wait().expect("wait");

    assert!(
        status.success(),
        "writing to inherited standard streams must succeed: {status:?}"
    );
}

#[test]
fn piped_stdout_and_stderr_carry_distinct_markers() {
    let config = config_with_probe_grant();
    let mut command = probe();
    command.args = vec!["echo-stdio".into()];
    command.stdout = StdioMode::Piped;
    command.stderr = StdioMode::Piped;

    let child = spawn_child(&config, command);
    let output = child.wait_with_output().expect("wait with output");

    assert!(output.status.success(), "echo-stdio failed: {output:?}");
    assert_eq!(output.stdout, b"stdout-marker\n");
    assert_eq!(output.stderr, b"stderr-marker\n");
}

#[test]
fn piped_stdin_reaches_the_child() {
    let config = config_with_probe_grant();
    let mut command = probe();
    command.args = vec!["stdin-echo".into()];
    command.stdin = StdioMode::Piped;
    command.stdout = StdioMode::Piped;

    let mut child = spawn_child(&config, command);
    let mut stdin = child.get_stdin().expect("piped stdin end");
    stdin
        .write_all(b"guardrail-stdin-roundtrip")
        .expect("write stdin");
    // Close our end so stdin-echo sees EOF and can finish.
    drop(stdin);

    let output = child.wait_with_output().expect("wait with output");
    assert!(output.status.success(), "stdin-echo failed: {output:?}");
    assert_eq!(output.stdout, b"guardrail-stdin-roundtrip");
}

#[test]
fn file_redirection_writes_distinct_markers() {
    let temp = TempPath::new();
    fs::create_dir_all(temp.path()).expect("create temp dir");
    let stdout_path = temp.path().join("stdout.txt");
    let stderr_path = temp.path().join("stderr.txt");

    // No fs grant covers the redirect targets: the child writes through the
    // inherited handles the parent opened, not by opening the paths itself.
    let config = config_with_probe_grant();
    let mut command = probe();
    command.args = vec!["echo-stdio".into()];
    command.stdout = StdioMode::File(fs::File::create(&stdout_path).expect("create stdout file"));
    command.stderr = StdioMode::File(fs::File::create(&stderr_path).expect("create stderr file"));

    let mut child = spawn_child(&config, command);
    let status = child.wait().expect("wait");

    assert!(status.success(), "echo-stdio failed: {status:?}");
    assert_eq!(
        fs::read_to_string(&stdout_path).expect("read stdout file"),
        "stdout-marker\n"
    );
    assert_eq!(
        fs::read_to_string(&stderr_path).expect("read stderr file"),
        "stderr-marker\n"
    );
}

#[test]
fn null_stdio_spawns_and_exits_cleanly() {
    let config = config_with_probe_grant();
    let mut command = probe();
    command.args = vec!["echo-stdio".into()];
    command.stdin = StdioMode::Null;
    command.stdout = StdioMode::Null;
    command.stderr = StdioMode::Null;

    let mut child = spawn_child(&config, command);
    let status = child.wait().expect("wait");

    assert!(
        status.success(),
        "writes to the null device must succeed: {status:?}"
    );
}

#[test]
fn unrelated_inheritable_handle_does_not_leak() {
    let temp = TempPath::new();
    fs::create_dir_all(temp.path()).expect("create temp dir");
    let secret = temp.path().join("secret.txt");
    fs::write(&secret, "secret").expect("write secret");

    let file = fs::File::open(&secret).expect("open secret");
    // Emulate a parent holding a leakable handle: std opens files
    // non-inheritable, so the flag must be set explicitly.
    // SAFETY: the handle is owned by `file`, which outlives both spawns below.
    let flagged = unsafe {
        SetHandleInformation(
            file.as_raw_handle(),
            HANDLE_FLAG_INHERIT,
            HANDLE_FLAG_INHERIT,
        )
    };
    assert_ne!(
        flagged,
        0,
        "make handle inheritable: {}",
        std::io::Error::last_os_error()
    );
    let raw = file.as_raw_handle() as usize;

    // Control: a plain std spawn passes bInheritHandles=TRUE with no handle
    // list, so its child CAN read the leaked handle. Proves the harness
    // leaks, so the denial below cannot pass vacuously.
    let control = std::process::Command::new(env!("CARGO_BIN_EXE_guardrail-windows-probe"))
        .args(["read-handle", &raw.to_string()])
        .status()
        .expect("spawn unsandboxed control probe");
    assert_eq!(
        control.code(),
        Some(0),
        "control: an unsandboxed child must inherit the flagged handle"
    );

    let config = config_with_probe_grant();
    let mut command = probe();
    command.args = vec!["read-handle".into(), raw.to_string().into()];
    let mut child = spawn_child(&config, command);

    // The uninherited raw value names no handle in the child, and hosts differ
    // in how that surfaces: ReadFile fails gracefully (probe exit 3), or the
    // child dies from a STATUS_INVALID_HANDLE exception where the sandbox runs
    // under strict handle checking. Both prove the handle never crossed; the
    // control spawn above rules out a vacuous pass.
    let code = child.wait().expect("wait").code();
    assert!(
        matches!(code, Some(3) | Some(STATUS_INVALID_HANDLE)),
        "an unrelated inheritable parent handle must not reach the sandboxed child: {code:?}"
    );
}

fn config_with_probe_grant() -> SandboxConfig {
    let mut env = BTreeMap::new();
    // AppContainer CreateProcess launches need these standard runtime values;
    // they are still explicit config inputs, so parent-only vars stay scrubbed.
    for key in ["SystemRoot", "LOCALAPPDATA", "USERPROFILE", "TEMP", "TMP"] {
        if let Ok(value) = std::env::var(key) {
            env.insert(key.to_string(), value);
        }
    }
    SandboxConfig {
        fs: vec![FsAccess::ReadAllow(probe_dir())],
        network: NetworkPolicy::Deny,
        linux_unix_sockets: vec![],
        limits: ResourceLimits::default(),
        env,
        darwin_sandbox_profiles: vec![],
        linux_user_namespaces: UserNamespacePolicy::Deny,
        windows_cache_namespace: Some(unique_namespace("stdio")),
    }
}

fn unique_namespace(label: &str) -> String {
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("guardrail-windows-{label}-{}-{counter}", std::process::id())
}

struct TempPath {
    path: PathBuf,
}

impl TempPath {
    fn new() -> Self {
        let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "guardrail-windows-stdio-{}-{counter}",
            std::process::id()
        ));
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempPath {
    fn drop(&mut self) {
        // Best-effort cleanup; a leftover temp dir must not fail the test.
        let _removed = fs::remove_dir_all(&self.path);
    }
}
