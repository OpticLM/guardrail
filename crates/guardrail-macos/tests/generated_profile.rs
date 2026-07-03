#![cfg(target_os = "macos")]

use guardrail_core::{Error, FsAccess, NetworkPolicy, SandboxConfig};
use guardrail_macos::MacosBackend;

mod common;

fn allowed(config: &SandboxConfig, args: &[&str]) -> bool {
    run(config, args).success()
}

fn run(config: &SandboxConfig, args: &[&str]) -> std::process::ExitStatus {
    let mut child = config
        .spawn_with(&MacosBackend::new(), common::probe(args))
        .expect("spawn");
    child.wait().expect("wait")
}

fn loopback_listener() -> (std::net::TcpListener, String) {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    (listener, addr)
}

#[test]
fn target_binary_runs_with_explicit_runtime_grants() {
    let config = common::base().build();
    let status = run(&config, &["noop"]);
    assert!(
        status.success(),
        "the sandboxed binary must run when read and execute are explicitly granted; status: {status}"
    );
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

    assert!(allowed(&config, &["read-file", public.to_str().unwrap()]));
    assert!(!allowed(&config, &["read-file", secret.to_str().unwrap()]));
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

    assert!(allowed(&config, &["read-file", public.to_str().unwrap()]));
    assert!(!allowed(&config, &["read-file", other.to_str().unwrap()]));
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

    assert!(allowed(&config, &["read-file", public.to_str().unwrap()]));
}

#[test]
fn deny_blocks_tcp_connect() {
    let (_listener, addr) = loopback_listener();
    let config = common::base().network(NetworkPolicy::Deny).build();
    assert!(
        !allowed(&config, &["tcp-connect", &addr]),
        "TCP connect must be blocked under Deny"
    );
}

#[test]
fn outbound_only_allows_tcp_connect() {
    let (_listener, addr) = loopback_listener();
    let config = common::base().network(NetworkPolicy::OutboundOnly).build();
    let status = run(&config, &["tcp-connect", &addr]);
    assert!(
        status.success(),
        "TCP connect must be allowed under OutboundOnly; status: {status}"
    );
}

#[test]
fn full_allows_tcp_connect() {
    let (_listener, addr) = loopback_listener();
    let config = common::base().network(NetworkPolicy::Full).build();
    let status = run(&config, &["tcp-connect", &addr]);
    assert!(
        status.success(),
        "TCP connect must be allowed under Full; status: {status}"
    );
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
