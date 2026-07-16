#![cfg(target_os = "linux")]

use std::process::{Command, ExitStatus};

use guardrail_core::{Backend, NetworkPolicy, SandboxConfig};
use guardrail_linux::LinuxBackend;

mod common;

fn probe(args: &[&str]) -> Command {
    common::probe(args)
}

fn status(config: &SandboxConfig, args: &[&str]) -> ExitStatus {
    let mut cmd = probe(args);
    cmd.env_clear();
    cmd.envs(&config.env);
    let mut child = LinuxBackend::new(config.clone())
        .expect("backend")
        .spawn(cmd)
        .expect("spawn");
    child.wait().expect("wait")
}

fn allowed(config: &SandboxConfig, args: &[&str]) -> bool {
    status(config, args).success()
}

/// True when the host kernel itself offers io_uring; it may be absent
/// (pre-5.1) or disabled via the `kernel.io_uring_disabled` sysctl, in which
/// case the io_uring policy tests cannot prove anything about the filter.
fn host_has_io_uring() -> bool {
    probe(&["io-uring-setup"])
        .status()
        .expect("run probe unsandboxed")
        .code()
        == Some(0)
}

const IO_URING_PROBES: &[&str] = &["io-uring-setup", "io-uring-enter", "io-uring-register"];

#[test]
fn deny_blocks_inet_socket_creation() {
    let mut config = common::base();
    config.network = NetworkPolicy::Deny;
    assert!(
        !allowed(&config, &["socket-inet"]),
        "creating an AF_INET socket must be blocked under Deny"
    );
}

#[test]
fn outbound_only_allows_socket_but_blocks_bind() {
    let mut config = common::base();
    config.network = NetworkPolicy::OutboundOnly;
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
    let mut config = common::base();
    config.network = NetworkPolicy::Full;
    assert!(
        allowed(&config, &["socket-inet"]),
        "socket creation must be allowed under Full"
    );
    assert!(
        allowed(&config, &["tcp-bind"]),
        "binding must be allowed under Full"
    );
}

#[test]
fn deny_and_outbound_only_block_io_uring_with_enosys() {
    if !host_has_io_uring() {
        eprintln!("skipping: io_uring unavailable on this host");
        return;
    }

    for policy in [NetworkPolicy::Deny, NetworkPolicy::OutboundOnly] {
        let mut config = common::base();
        config.network = policy;
        for &probe in IO_URING_PROBES {
            // Exit 3 is reserved for ENOSYS by these probe modes; unexpected
            // host errors exit 2 and SIGSYS has no exit code.
            assert_eq!(
                status(&config, &[probe]).code(),
                Some(3),
                "{probe} must fail with ENOSYS under {policy:?}"
            );
        }
    }
}

#[test]
fn full_allows_io_uring_syscalls() {
    if !host_has_io_uring() {
        eprintln!("skipping: io_uring unavailable on this host");
        return;
    }
    let mut config = common::base();
    config.network = NetworkPolicy::Full;
    for &probe in IO_URING_PROBES {
        assert!(
            allowed(&config, &[probe]),
            "{probe} must be allowed under Full"
        );
    }
}
