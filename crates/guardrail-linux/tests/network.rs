#![cfg(target_os = "linux")]

use std::process::Command;

use guardrail_core::{NetworkPolicy, SandboxConfig};
use guardrail_linux::LinuxBackend;

mod common;

fn probe(args: &[&str]) -> Command {
    common::probe(args)
}

fn allowed(config: &SandboxConfig, args: &[&str]) -> bool {
    let mut child = config
        .spawn_with(&LinuxBackend::new(), probe(args))
        .expect("spawn");
    child.wait().expect("wait").success()
}

#[test]
fn deny_blocks_inet_socket_creation() {
    let config = common::base().network(NetworkPolicy::Deny).build();
    assert!(
        !allowed(&config, &["socket-inet"]),
        "creating an AF_INET socket must be blocked under Deny"
    );
}

#[test]
fn outbound_only_allows_socket_but_blocks_bind() {
    let config = common::base().network(NetworkPolicy::OutboundOnly).build();
    assert!(
        allowed(&config, &["socket-inet"]),
        "AF_INET socket creation must be allowed under OutboundOnly"
    );
    assert!(
        !allowed(&config, &["tcp-bind"]),
        "binding/listening must be blocked under OutboundOnly"
    );
}

#[test]
fn full_allows_socket_and_bind() {
    let config = common::base().network(NetworkPolicy::Full).build();
    assert!(
        allowed(&config, &["socket-inet"]),
        "socket creation must be allowed under Full"
    );
    assert!(
        allowed(&config, &["tcp-bind"]),
        "binding must be allowed under Full"
    );
}
