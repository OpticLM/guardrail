#![cfg(target_os = "macos")]

use guardrail_core::{Error, NetworkPolicy, SandboxConfig};
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
fn read_grant_does_not_allow_execute() {
    let config = common::read_only_base().build();
    let result = config.spawn_with(&MacosBackend::new(), common::probe(&["noop"]));

    match result {
        Err(Error::Spawn(_)) => {}
        Err(other) => panic!("expected spawn permission denial, got {other:?}"),
        Ok(mut child) => assert!(
            !child.wait().expect("wait").success(),
            "read-only filesystem grants must not allow executing the probe"
        ),
    }
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
