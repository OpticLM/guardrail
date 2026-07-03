#![cfg(windows)]

use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use guardrail_core::{FsAccess, NetworkPolicy, SandboxBuilder, SandboxConfig};
use guardrail_windows::WindowsBackend;

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
fn filesystem_read_is_denied_without_grant() {
    let temp = TempPath::new();
    fs::create_dir_all(temp.path()).expect("create temp dir");
    let file = temp.path().join("input.txt");
    fs::write(&file, "guardrail").expect("write input");

    let config = builder_with_system_root()
        .fs([FsAccess::ReadAllow(probe_dir())])
        .build();
    let mut command = probe();
    command.arg("read-file").arg(&file);

    let mut child = config
        .spawn_with(&WindowsBackend::new(), command)
        .expect("spawn probe");
    let status = child.wait().expect("wait");

    assert!(
        !status.success(),
        "file should not be readable without a declared grant"
    );
}

#[test]
fn read_grant_allows_reading_a_declared_directory() {
    let temp = TempPath::new();
    fs::create_dir_all(temp.path()).expect("create temp dir");
    let file = temp.path().join("input.txt");
    fs::write(&file, "guardrail").expect("write input");

    let config = builder_with_system_root()
        .fs([
            FsAccess::ReadAllow(probe_dir()),
            FsAccess::ReadAllow(temp.path().into()),
        ])
        .build();
    let mut command = probe();
    command.arg("read-file").arg(&file);

    let mut child = config
        .spawn_with(&WindowsBackend::new(), command)
        .expect("spawn with read grant");
    let status = child.wait().expect("wait");

    assert!(status.success(), "read-granted file should be readable");
}

#[test]
fn write_is_denied_under_read_grant() {
    let temp = TempPath::new();
    fs::create_dir_all(temp.path()).expect("create temp dir");
    let file = temp.path().join("output.txt");

    let config = builder_with_system_root()
        .fs([
            FsAccess::ReadAllow(probe_dir()),
            FsAccess::ReadAllow(temp.path().into()),
        ])
        .build();
    let mut command = probe();
    command.arg("write-file").arg(&file);

    let mut child = config
        .spawn_with(&WindowsBackend::new(), command)
        .expect("spawn with read grant");
    let status = child.wait().expect("wait");

    assert!(
        !status.success(),
        "read grant must not allow writing under the directory"
    );
    assert!(
        !file.exists(),
        "read-only grant should not create the output file"
    );
}

#[test]
fn write_grant_allows_writing_under_declared_directory() {
    let temp = TempPath::new();
    fs::create_dir_all(temp.path()).expect("create temp dir");
    let file = temp.path().join("output.txt");

    let config = builder_with_system_root()
        .fs([
            FsAccess::ReadAllow(probe_dir()),
            FsAccess::WriteAllow(temp.path().into()),
        ])
        .build();
    let mut command = probe();
    command.arg("write-file").arg(&file);

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
fn read_allow_then_read_deny_denies_child_but_allows_sibling() {
    let temp = TempPath::new();
    fs::create_dir_all(temp.path()).expect("create temp dir");
    let public = temp.path().join("public.txt");
    let secret = temp.path().join("secret.txt");
    fs::write(&public, "public").expect("write public");
    fs::write(&secret, "secret").expect("write secret");

    let config = builder_with_system_root()
        .fs([
            FsAccess::ReadAllow(probe_dir()),
            FsAccess::ReadAllow(temp.path().into()),
            FsAccess::ReadDeny(secret.clone()),
        ])
        .build();

    assert!(probe_file_allowed(&config, "read-file", &public));
    assert!(!probe_file_allowed(&config, "read-file", &secret));
}

#[test]
fn read_deny_then_read_allow_reopens_child_only() {
    let temp = TempPath::new();
    fs::create_dir_all(temp.path()).expect("create temp dir");
    let public = temp.path().join("public.txt");
    let other = temp.path().join("other.txt");
    fs::write(&public, "public").expect("write public");
    fs::write(&other, "other").expect("write other");

    let config = builder_with_system_root()
        .fs([
            FsAccess::ReadAllow(probe_dir()),
            FsAccess::ReadDeny(temp.path().into()),
            FsAccess::ReadAllow(public.clone()),
        ])
        .build();

    assert!(probe_file_allowed(&config, "read-file", &public));
    assert!(!probe_file_allowed(&config, "read-file", &other));
}

#[test]
fn later_read_allow_overrides_same_path_deny() {
    let temp = TempPath::new();
    fs::create_dir_all(temp.path()).expect("create temp dir");
    let public = temp.path().join("public.txt");
    fs::write(&public, "public").expect("write public");

    let config = builder_with_system_root()
        .fs([
            FsAccess::ReadAllow(probe_dir()),
            FsAccess::ReadAllow(temp.path().into()),
            FsAccess::ReadDeny(temp.path().into()),
            FsAccess::ReadAllow(temp.path().into()),
        ])
        .build();

    assert!(probe_file_allowed(&config, "read-file", &public));
}

#[test]
fn later_read_deny_overrides_same_path_allow() {
    let temp = TempPath::new();
    fs::create_dir_all(temp.path()).expect("create temp dir");
    let secret = temp.path().join("secret.txt");
    fs::write(&secret, "secret").expect("write secret");

    let config = builder_with_system_root()
        .fs([
            FsAccess::ReadAllow(probe_dir()),
            FsAccess::ReadAllow(temp.path().into()),
            FsAccess::ReadDeny(temp.path().into()),
        ])
        .build();

    assert!(!probe_file_allowed(&config, "read-file", &secret));
}

#[test]
fn write_rule_does_not_grant_read() {
    let temp = TempPath::new();
    fs::create_dir_all(temp.path()).expect("create temp dir");
    let output = temp.path().join("output.txt");
    let secret = temp.path().join("secret.txt");
    fs::write(&secret, "secret").expect("write secret");

    let config = builder_with_system_root()
        .fs([
            FsAccess::ReadAllow(probe_dir()),
            FsAccess::WriteAllow(temp.path().into()),
        ])
        .build();

    assert!(probe_file_allowed(&config, "write-file", &output));
    assert!(!probe_file_allowed(&config, "read-file", &secret));
}

#[test]
fn default_network_deny_blocks_outbound_tcp_connect() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind local listener");
    let port = listener
        .local_addr()
        .expect("listener address")
        .port()
        .to_string();

    let config = builder_with_system_root()
        .fs([FsAccess::ReadAllow(probe_dir())])
        .network(NetworkPolicy::Deny)
        .build();
    let mut command = probe();
    command.args(["tcp-connect", "127.0.0.1", &port]);

    let mut child = config
        .spawn_with(&WindowsBackend::new(), command)
        .expect("spawn probe");
    let status = child.wait().expect("wait");

    assert!(
        !status.success(),
        "default network deny should block outbound TCP connect"
    );
}

#[test]
#[ignore = "requires host AppContainer loopback support for the per-run test profile"]
fn outbound_only_allows_loopback_connect_when_host_allows_appcontainer_loopback() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind local listener");
    let port = listener
        .local_addr()
        .expect("listener address")
        .port()
        .to_string();

    let config = builder_with_system_root()
        .fs([FsAccess::ReadAllow(probe_dir())])
        .network(NetworkPolicy::OutboundOnly)
        .build();
    let mut command = probe();
    command.args(["tcp-connect", "127.0.0.1", &port]);

    let mut child = config
        .spawn_with(&WindowsBackend::new(), command)
        .expect("spawn probe");
    let status = child.wait().expect("wait");

    assert!(
        status.success(),
        "outbound-only should allow loopback connect when the host permits AppContainer loopback"
    );
}

#[test]
fn full_network_allows_tcp_bind() {
    let config = builder_with_system_root()
        .fs([FsAccess::ReadAllow(probe_dir())])
        .network(NetworkPolicy::Full)
        .build();
    let mut command = probe();
    command.arg("tcp-bind");

    let mut child = config
        .spawn_with(&WindowsBackend::new(), command)
        .expect("spawn probe");
    let status = child.wait().expect("wait");

    assert!(
        status.success(),
        "full network policy should allow TCP bind"
    );
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

fn probe_file_allowed(config: &SandboxConfig, operation: &str, path: &Path) -> bool {
    let mut command = probe();
    command.arg(operation).arg(path);
    let mut child = config
        .spawn_with(&WindowsBackend::new(), command)
        .expect("spawn probe");
    child.wait().expect("wait").success()
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
