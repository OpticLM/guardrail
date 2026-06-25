#![cfg(windows)]

use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use guardrail_core::SandboxBuilder;
use guardrail_windows::WindowsBackend;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_TERMINATE, TerminateProcess};

fn probe() -> Command {
    Command::new(env!("CARGO_BIN_EXE_guardrail-windows-probe"))
}

fn probe_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_guardrail-windows-probe"))
        .parent()
        .expect("probe binary has a parent directory")
        .to_path_buf()
}

#[test]
fn default_config_runs_command_under_job_object() {
    let config = builder_with_windows_runtime_env().build();
    let mut command = Command::new("cmd");
    command.args(["/C", "exit", "0"]);

    let mut child = config
        .spawn_with(&WindowsBackend::new(), command)
        .expect("spawn under Windows Job Object");
    let status = child.wait().expect("wait");

    assert!(status.success(), "cmd /C exit 0 should succeed");
}

#[test]
fn memory_limit_blocks_large_allocation() {
    let config = builder_with_windows_runtime_env()
        .allow_read(probe_dir())
        .memory_limit_mb(64)
        .build();
    let mut command = probe();
    command.args(["alloc", "512"]);

    let mut child = config
        .spawn_with(&WindowsBackend::new(), command)
        .expect("spawn probe");
    let status = child.wait().expect("wait");

    assert!(
        !status.success(),
        "allocation of 512 MiB must fail under a 64 MiB Job memory limit"
    );
}

#[test]
fn without_limit_the_same_allocation_succeeds() {
    let config = builder_with_windows_runtime_env()
        .allow_read(probe_dir())
        .build();
    let mut command = probe();
    command.args(["alloc", "512"]);

    let mut child = config
        .spawn_with(&WindowsBackend::new(), command)
        .expect("spawn probe");
    let status = child.wait().expect("wait");

    assert!(
        status.success(),
        "512 MiB should allocate when unconstrained"
    );
}

#[test]
fn cpu_time_limit_kills_busy_loop() {
    let config = builder_with_windows_runtime_env()
        .allow_read(probe_dir())
        .cpu_time_limit_secs(1)
        .build();
    let mut command = probe();
    command.arg("spin");

    let mut child = config
        .spawn_with(&WindowsBackend::new(), command)
        .expect("spawn probe");
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
    let config = builder_with_windows_runtime_env().max_processes(1).build();
    let mut command = Command::new("cmd");
    command.args(["/C", "start", "/B", "cmd", "/C", "exit", "0"]);

    let mut child = config
        .spawn_with(&WindowsBackend::new(), command)
        .expect("spawn under Windows Job Object");
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

fn builder_with_windows_runtime_env() -> SandboxBuilder {
    let mut builder = SandboxBuilder::new();
    for key in ["SystemRoot", "LOCALAPPDATA", "USERPROFILE", "TEMP", "TMP"] {
        if let Ok(value) = std::env::var(key) {
            builder = builder.env(key, value);
        }
    }
    builder
}
