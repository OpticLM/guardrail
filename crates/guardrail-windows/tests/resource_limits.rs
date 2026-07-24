#![cfg(windows)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use guardrail_core::{
    Backend, FsAccess, NetworkPolicy, ResourceLimits, SandboxCommand, SandboxConfig,
    UserNamespacePolicy,
};
use guardrail_windows::WindowsBackend;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_TERMINATE, TerminateProcess};

static NAMESPACE_COUNTER: AtomicU64 = AtomicU64::new(1);

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
fn default_config_runs_command_under_job_object() {
    let config = builder_with_windows_runtime_env();
    let mut command = SandboxCommand::new("cmd");
    command.args = vec!["/C".into(), "exit".into(), "0".into()];

    let mut child = spawn_child(&config, command);
    let status = child.wait().expect("wait");

    assert!(status.success(), "cmd /C exit 0 should succeed");
}

#[test]
fn memory_limit_blocks_large_allocation() {
    let mut config = builder_with_windows_runtime_env();
    config.fs.extend([FsAccess::ReadAllow(probe_dir())]);
    config.limits.memory_bytes = Some(64 * 1024 * 1024);
    let mut command = probe();
    command.args = vec!["alloc".into(), "512".into()];

    let mut child = spawn_child(&config, command);
    let status = child.wait().expect("wait");

    assert!(
        !status.success(),
        "allocation of 512 MiB must fail under a 64 MiB Job memory limit"
    );
}

#[test]
fn without_limit_the_same_allocation_succeeds() {
    let mut config = builder_with_windows_runtime_env();
    config.fs.extend([FsAccess::ReadAllow(probe_dir())]);
    let mut command = probe();
    command.args = vec!["alloc".into(), "512".into()];

    let mut child = spawn_child(&config, command);
    let status = child.wait().expect("wait");

    assert!(
        status.success(),
        "512 MiB should allocate when unconstrained"
    );
}

#[test]
fn cpu_time_limit_kills_busy_loop() {
    let mut config = builder_with_windows_runtime_env();
    config.fs.extend([FsAccess::ReadAllow(probe_dir())]);
    config.limits.cpu_time_secs = Some(1);
    let mut command = probe();
    command.args = vec!["spin".into()];

    let mut child = spawn_child(&config, command);
    let (cancel_watchdog, watchdog, watchdog_fired) =
        spawn_watchdog(child.id(), Duration::from_secs(10));

    let start = Instant::now();
    let status = child.wait().expect("wait");
    let elapsed = start.elapsed();
    let _ = cancel_watchdog.send(());
    watchdog.join().expect("watchdog thread should not panic");

    assert!(
        !watchdog_fired.load(Ordering::SeqCst),
        "spinner exceeded the watchdog timeout; CPU limit did not terminate it"
    );
    assert!(
        !status.success(),
        "spinner must be killed by the CPU limit, not exit cleanly"
    );
    assert!(
        elapsed < Duration::from_secs(10),
        "spinner should die from the CPU limit well under 10s (took {elapsed:?})"
    );
}

#[test]
#[ignore = "Windows nested process-count behavior is host-sensitive; run manually on a quiet machine"]
fn process_limit_is_applied() {
    let mut config = builder_with_windows_runtime_env();
    config.limits.max_processes = Some(1);
    let mut command = SandboxCommand::new("cmd");
    command.args = vec![
        "/C".into(),
        "start".into(),
        "/B".into(),
        "cmd".into(),
        "/C".into(),
        "exit".into(),
        "0".into(),
    ];

    let mut child = spawn_child(&config, command);
    let status = child.wait().expect("wait");

    assert!(
        !status.success(),
        "a max_processes(1) job should not allow a child process"
    );
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

fn builder_with_windows_runtime_env() -> SandboxConfig {
    let mut env = BTreeMap::new();
    for key in ["SystemRoot", "LOCALAPPDATA", "USERPROFILE", "TEMP", "TMP"] {
        if let Ok(value) = std::env::var(key) {
            env.insert(key.to_string(), value);
        }
    }
    // Bare names like `cmd` resolve against this PATH only (issue #23); the
    // supervisor's lookup context is never consulted.
    if let Ok(system_root) = std::env::var("SystemRoot") {
        env.insert("PATH".to_string(), format!(r"{system_root}\System32"));
    }
    SandboxConfig {
        fs: vec![],
        network: NetworkPolicy::Deny,
        linux_unix_sockets: vec![],
        limits: ResourceLimits::default(),
        env,
        darwin_sandbox_profiles: vec![],
        linux_user_namespaces: UserNamespacePolicy::Deny,
        windows_cache_namespace: Some(unique_namespace("resource-limits")),
        windows_manifest_dir: Some(std::env::temp_dir().join("guardrail-test-manifests")),
        windows_acl_verification: guardrail_core::WindowsAclVerification::default(),
    }
}

fn unique_namespace(label: &str) -> String {
    let counter = NAMESPACE_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("guardrail-windows-{label}-{}-{counter}", std::process::id())
}
