#![cfg(target_os = "macos")]

use std::fmt;
use std::process::{ExitStatus, Stdio};

use guardrail_core::{Error, FsAccess, NetworkPolicy, SandboxConfig};
use guardrail_macos::MacosBackend;

mod common;

fn assert_allowed(config: &SandboxConfig, args: &[&str]) {
    let result = run(config, args);
    assert!(
        result.status.success(),
        "expected {args:?} to be allowed\n{result}\nconfig: {config:#?}"
    );
}

fn assert_denied(config: &SandboxConfig, args: &[&str]) {
    let result = run(config, args);
    assert!(
        !result.status.success(),
        "expected {args:?} to be denied\n{result}\nconfig: {config:#?}"
    );
}

fn run(config: &SandboxConfig, args: &[&str]) -> RunResult {
    let mut command = common::probe(args);
    command.stdout(Stdio::piped()).stderr(Stdio::piped());

    let child = config
        .spawn_with(&MacosBackend::new(), command)
        .unwrap_or_else(|err| panic!("spawn failed for {args:?}: {err:?}\nconfig: {config:#?}"));
    let output = child.into_inner().wait_with_output().expect("wait");

    RunResult {
        status: output.status,
        stdout: output.stdout,
        stderr: output.stderr,
    }
}

struct RunResult {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl fmt::Display for RunResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "status: {}", self.status)?;
        if !self.stdout.is_empty() {
            writeln!(f, "stdout:\n{}", String::from_utf8_lossy(&self.stdout))?;
        }
        if !self.stderr.is_empty() {
            writeln!(f, "stderr:\n{}", String::from_utf8_lossy(&self.stderr))?;
        }
        Ok(())
    }
}

fn loopback_listener() -> (std::net::TcpListener, String) {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    (listener, addr)
}

#[test]
fn target_binary_runs_with_explicit_runtime_grants() {
    let config = common::base().build();
    assert_allowed(&config, &["noop"]);
}

#[test]
fn read_rule_does_not_grant_execute() {
    let config = common::read_only_base().build();
    let result = config.spawn_with(&MacosBackend::new(), common::probe(&["noop"]));

    match result {
        Err(Error::Spawn(_)) => {}
        Err(other) => panic!("expected spawn permission denial, got {other:?}"),
        Ok(mut child) => assert!(
            !child.wait().expect("wait").success(),
            "read-only filesystem rules must not allow executing the probe"
        ),
    }
}

#[test]
fn read_allow_then_read_deny_denies_child_but_allows_sibling() {
    let temp_dir = TempDir::create("ordered-deny-child");
    let public = temp_dir.write("public.txt", b"public");
    let secret = temp_dir.write("secret.txt", b"secret");

    let config = common::base()
        .fs([
            FsAccess::ReadAllow(temp_dir.path().into()),
            FsAccess::ReadDeny(secret.clone()),
        ])
        .build();

    assert_allowed(&config, &["read-file", public.to_str().unwrap()]);
    assert_denied(&config, &["read-file", secret.to_str().unwrap()]);
}

#[test]
fn read_deny_then_read_allow_reopens_child_only() {
    let temp_dir = TempDir::create("ordered-reopen-child");
    let public = temp_dir.write("public.txt", b"public");
    let other = temp_dir.write("other.txt", b"other");

    let config = common::base()
        .fs([
            FsAccess::ReadDeny(temp_dir.path().into()),
            FsAccess::ReadAllow(public.clone()),
        ])
        .build();

    assert_allowed(&config, &["read-file", public.to_str().unwrap()]);
    assert_denied(&config, &["read-file", other.to_str().unwrap()]);
}

#[test]
fn later_read_allow_overrides_same_path_deny() {
    let temp_dir = TempDir::create("ordered-same-path");
    let public = temp_dir.write("public.txt", b"public");

    let config = common::base()
        .fs([
            FsAccess::ReadAllow(temp_dir.path().into()),
            FsAccess::ReadDeny(temp_dir.path().into()),
            FsAccess::ReadAllow(temp_dir.path().into()),
        ])
        .build();

    assert_allowed(&config, &["read-file", public.to_str().unwrap()]);
}

#[test]
fn deny_blocks_tcp_connect() {
    let (_listener, addr) = loopback_listener();
    let config = common::base().network(NetworkPolicy::Deny).build();
    assert_denied(&config, &["tcp-connect", &addr]);
}

#[test]
fn outbound_only_allows_tcp_connect() {
    let (_listener, addr) = loopback_listener();
    let config = common::base().network(NetworkPolicy::OutboundOnly).build();
    assert_allowed(&config, &["tcp-connect", &addr]);
}

#[test]
fn full_allows_tcp_connect() {
    let (_listener, addr) = loopback_listener();
    let config = common::base().network(NetworkPolicy::Full).build();
    assert_allowed(&config, &["tcp-connect", &addr]);
}

struct TempDir {
    path: std::path::PathBuf,
}

impl TempDir {
    fn create(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "guardrail-macos-{label}-{}-{}",
            std::process::id(),
            unique_suffix()
        ));
        std::fs::create_dir(&path).unwrap();
        Self { path }
    }

    fn path(&self) -> &std::path::Path {
        &self.path
    }

    fn write(&self, name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let path = self.path.join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn unique_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}
