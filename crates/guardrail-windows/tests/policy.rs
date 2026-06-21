#![cfg(windows)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use guardrail_core::{NetworkPolicy, SandboxBuilder};
use guardrail_windows::WindowsBackend;

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(1);

#[test]
fn default_network_deny_still_launches_process_in_appcontainer() {
    let config = builder_with_system_root().build();
    let mut command = Command::new("cmd");
    command.args(["/C", "exit", "0"]);

    let mut child = config
        .spawn_with(&WindowsBackend::new(), command)
        .expect("spawn with default AppContainer policy");
    let status = child.wait().expect("wait");

    assert!(status.success(), "cmd /C exit 0 should succeed");
}

#[test]
fn read_grant_allows_reading_a_declared_directory() {
    let temp = TempPath::new();
    fs::create_dir_all(temp.path()).expect("create temp dir");
    let file = temp.path().join("input.txt");
    fs::write(&file, "guardrail").expect("write input");

    let config = builder_with_system_root().allow_read(temp.path()).build();
    let mut command = Command::new("cmd");
    command.args(["/C", "type", &file.display().to_string()]);

    let mut child = config
        .spawn_with(&WindowsBackend::new(), command)
        .expect("spawn with read grant");
    let status = child.wait().expect("wait");

    assert!(status.success(), "read-granted file should be readable");
}

#[test]
fn write_grant_allows_writing_under_declared_directory() {
    let temp = TempPath::new();
    fs::create_dir_all(temp.path()).expect("create temp dir");
    let file = temp.path().join("output.txt");

    let config = builder_with_system_root().allow_write(temp.path()).build();
    let mut command = Command::new("cmd");
    command.current_dir(temp.path());
    command.args(["/C", "echo guardrail> output.txt"]);

    let mut child = config
        .spawn_with(&WindowsBackend::new(), command)
        .expect("spawn with write grant");
    let status = child.wait().expect("wait");

    assert!(
        status.success(),
        "write-granted directory should be writable"
    );
    assert!(file.exists(), "write-granted file should be created");
}

#[test]
#[ignore = "plan 010 adds a deterministic Windows probe and AppContainer loopback setup"]
fn outbound_only_allows_loopback_connect_when_host_allows_appcontainer_loopback() {
    let _config = SandboxBuilder::new()
        .network(NetworkPolicy::OutboundOnly)
        .build();
    // Manual follow-up once plan 010 lands:
    // cargo test -p guardrail-windows --test policy -- --ignored
}

#[test]
#[ignore = "plan 010 adds a deterministic Windows probe and AppContainer loopback setup"]
fn default_network_deny_blocks_outbound_tcp_connect() {
    let _config = SandboxBuilder::new().network(NetworkPolicy::Deny).build();
    // Manual follow-up once plan 010 lands:
    // cargo test -p guardrail-windows --test policy -- --ignored
}

struct TempPath {
    path: PathBuf,
}

fn builder_with_system_root() -> SandboxBuilder {
    let mut builder = SandboxBuilder::new();
    for key in ["SystemRoot", "LOCALAPPDATA", "USERPROFILE", "TEMP", "TMP"] {
        if let Ok(value) = std::env::var(key) {
            builder = builder.env(key, value);
        }
    }
    builder
}

impl TempPath {
    fn new() -> Self {
        let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "guardrail-windows-policy-{}-{counter}",
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
