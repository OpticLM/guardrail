use std::process::{Command, Stdio};

use guardrail_core::{NetworkPolicy, SandboxBuilder, SandboxConfig};
use guardrail_linux::LinuxBackend;

fn probe(args: &[&str]) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_guardrail-probe"));
    c.args(args).stdout(Stdio::null()).stderr(Stdio::null());
    c
}

fn allowed(config: &SandboxConfig, args: &[&str]) -> bool {
    let mut child = config
        .spawn_with(&LinuxBackend::new(), probe(args))
        .expect("spawn");
    child.wait().expect("wait").success()
}

/// Grant read on the binary's dir so it loads under any Landlock rules that may
/// also be active; network tests should not be coupled to FS confinement.
fn base() -> SandboxBuilder {
    let exe = std::path::PathBuf::from(env!("CARGO_BIN_EXE_guardrail-probe"));
    SandboxBuilder::new().allow_read(exe.parent().unwrap().to_path_buf())
}

#[test]
fn deny_blocks_inet_socket_creation() {
    let config = base().network(NetworkPolicy::Deny).build();
    assert!(
        !allowed(&config, &["socket-inet"]),
        "creating an AF_INET socket must be blocked under Deny"
    );
}

#[test]
fn outbound_only_allows_socket_but_blocks_bind() {
    let config = base().network(NetworkPolicy::OutboundOnly).build();
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
    let config = base().network(NetworkPolicy::Full).build();
    assert!(
        allowed(&config, &["socket-inet"]),
        "socket creation must be allowed under Full"
    );
    assert!(
        allowed(&config, &["tcp-bind"]),
        "binding must be allowed under Full"
    );
}
