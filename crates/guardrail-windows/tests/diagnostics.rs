#![cfg(windows)]

use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use guardrail_core::{NetworkPolicy, SandboxBuilder, SandboxConfig, ViolationKind};
use guardrail_windows::WindowsBackend;
use guardrail_windows::diagnostics::explain;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_TERMINATE, TerminateProcess};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(1);

fn probe() -> Command {
    Command::new(env!("CARGO_BIN_EXE_guardrail-windows-probe"))
}

fn probe_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_guardrail-windows-probe"))
        .parent()
        .expect("probe binary has a parent directory")
        .to_path_buf()
}

fn base_builder() -> SandboxBuilder {
    builder_with_windows_runtime_env().allow_read(probe_dir())
}

fn run(config: &SandboxConfig, command: Command) -> ExitStatus {
    let mut child = config
        .spawn_with(&WindowsBackend::new(), command)
        .expect("spawn probe");
    child.wait().expect("wait")
}

#[test]
fn success_yields_no_violation() {
    let config = base_builder().env("GREETING", "hello").build();
    let mut command = probe();
    command.args(["check-env", "GREETING", "hello"]);

    let status = run(&config, command);

    assert!(status.success());
    assert!(explain(&config, status).is_none());
}

#[test]
fn memory_limit_is_diagnosed_as_resource_limit() {
    let config = base_builder().memory_limit_mb(64).build();
    let mut command = probe();
    command.args(["alloc", "512"]);

    let status = run(&config, command);
    let violation = explain(&config, status).expect("should diagnose resource limit");

    assert_eq!(violation.kind, ViolationKind::ResourceLimit);
    assert!(
        violation
            .suggestions
            .iter()
            .any(|suggestion| suggestion.contains(".memory_limit_mb"))
    );
}

#[test]
fn cpu_limit_is_diagnosed_as_resource_limit() {
    let config = base_builder().cpu_time_limit_secs(1).build();
    let mut command = probe();
    command.arg("spin");

    let status = run_with_watchdog(&config, command, Duration::from_secs(10));
    let violation = explain(&config, status).expect("should diagnose resource limit");

    assert_eq!(violation.kind, ViolationKind::ResourceLimit);
    assert!(
        violation
            .suggestions
            .iter()
            .any(|suggestion| suggestion.contains(".cpu_time_limit_secs"))
    );
}

#[test]
fn filesystem_denial_suggests_file_grants() {
    let temp = TempPath::new();
    fs::create_dir_all(temp.path()).expect("create temp dir");
    let file = temp.path().join("input.txt");
    fs::write(&file, "guardrail").expect("write input");

    let config = base_builder().network(NetworkPolicy::Full).build();
    let mut command = probe();
    command.arg("read-file").arg(&file);

    let status = run(&config, command);
    let violation = explain(&config, status).expect("should diagnose policy failure");

    assert_eq!(violation.kind, ViolationKind::Filesystem);
    assert!(violation.suggestions.iter().any(
        |suggestion| suggestion.contains(".allow_read") || suggestion.contains(".allow_write")
    ));
}

#[test]
fn network_denial_suggests_network_policy() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind local listener");
    let port = listener
        .local_addr()
        .expect("listener address")
        .port()
        .to_string();

    let config = base_builder().network(NetworkPolicy::Deny).build();
    let mut command = probe();
    command.args(["tcp-connect", "127.0.0.1", &port]);

    let status = run(&config, command);
    let violation = explain(&config, status).expect("should diagnose policy failure");

    assert_eq!(violation.kind, ViolationKind::Unknown);
    assert!(
        violation
            .suggestions
            .iter()
            .any(|suggestion| suggestion.contains(".network("))
    );
}

#[test]
fn violation_display_includes_summary_and_suggestion_bullets() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind local listener");
    let port = listener
        .local_addr()
        .expect("listener address")
        .port()
        .to_string();

    let config = base_builder().network(NetworkPolicy::Deny).build();
    let mut command = probe();
    command.args(["tcp-connect", "127.0.0.1", &port]);

    let status = run(&config, command);
    let violation = explain(&config, status).expect("should diagnose policy failure");
    let rendered = violation.to_string();

    assert!(rendered.contains(&violation.summary));
    assert!(
        rendered.contains("\n  - "),
        "Display should bullet the suggestions"
    );
}

fn run_with_watchdog(config: &SandboxConfig, command: Command, timeout: Duration) -> ExitStatus {
    let mut child = config
        .spawn_with(&WindowsBackend::new(), command)
        .expect("spawn probe");
    let (cancel_watchdog, watchdog, watchdog_fired) = spawn_watchdog(child.id(), timeout);
    let status = child.wait().expect("wait");
    let _ = cancel_watchdog.send(());
    watchdog.join().expect("watchdog thread should not panic");
    assert!(
        !watchdog_fired.load(Ordering::SeqCst),
        "child exceeded watchdog timeout before the sandbox terminated it"
    );
    status
}

fn spawn_watchdog(
    pid: u32,
    timeout: Duration,
) -> (mpsc::Sender<()>, thread::JoinHandle<()>, Arc<AtomicBool>) {
    let (tx, rx) = mpsc::channel();
    let fired = Arc::new(AtomicBool::new(false));
    let thread_fired = Arc::clone(&fired);
    let handle = thread::spawn(move || {
        if rx.recv_timeout(timeout).is_err() {
            thread_fired.store(true, Ordering::SeqCst);
            terminate_process(pid);
        }
    });
    (tx, handle, fired)
}

fn terminate_process(pid: u32) {
    // SAFETY: best-effort test cleanup. The PID comes from the just-spawned
    // sandbox child, and the handle is closed if it can be opened.
    unsafe {
        let process = OpenProcess(PROCESS_TERMINATE, 0, pid);
        if !process.is_null() {
            let _ = TerminateProcess(process, 1);
            let _ = CloseHandle(process);
        }
    }
}

fn builder_with_windows_runtime_env() -> SandboxBuilder {
    let mut builder = SandboxBuilder::new();
    for key in ["SystemRoot", "LOCALAPPDATA", "USERPROFILE", "TEMP", "TMP"] {
        if let Ok(value) = std::env::var(key) {
            builder = builder.env(key, value);
        }
    }
    builder
}

struct TempPath {
    path: PathBuf,
}

impl TempPath {
    fn new() -> Self {
        let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "guardrail-windows-diagnostics-{}-{counter}",
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
        let _ = fs::remove_dir_all(&self.path);
    }
}
