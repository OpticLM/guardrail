#![cfg(target_os = "linux")]

use std::os::unix::process::ExitStatusExt;
use std::process::{Command, ExitStatus};

use guardrail_core::{Backend, IpcPolicy, NetworkPolicy, SandboxConfig};
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

fn blocked_by_seccomp(config: &SandboxConfig, args: &[&str]) -> bool {
    status(config, args).signal() == Some(libc::SIGSYS)
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
        blocked_by_seccomp(&config, &["socket-inet"]),
        "creating an AF_INET socket must be blocked under Deny"
    );
}

#[test]
fn deny_blocks_netlink_socket_creation() {
    let mut config = common::base();
    config.network = NetworkPolicy::Deny;
    assert!(
        blocked_by_seccomp(&config, &["socket-netlink"]),
        "creating an AF_NETLINK socket must be blocked under Deny"
    );
}

#[test]
fn deny_blocks_packet_socket_creation() {
    let mut config = common::base();
    config.network = NetworkPolicy::Deny;
    assert!(
        blocked_by_seccomp(&config, &["socket-packet"]),
        "creating an AF_PACKET socket must be blocked under Deny"
    );
}

#[test]
fn deny_blocks_vsock_socket_creation() {
    let mut config = common::base();
    config.network = NetworkPolicy::Deny;
    assert!(
        blocked_by_seccomp(&config, &["socket-vsock"]),
        "creating an AF_VSOCK socket must be blocked under Deny"
    );
}

#[test]
fn deny_leaves_unix_sockets_to_the_ipc_policy() {
    let mut config = common::base();
    config.network = NetworkPolicy::Deny;
    // Relaxed IPC isolates the network filter: AF_UNIX must pass it.
    config.ipc = IpcPolicy::Relaxed;
    assert!(
        allowed(&config, &["socket-unix"]),
        "the network Deny filter must not block AF_UNIX; that is IpcPolicy's job"
    );
}

#[test]
fn outbound_only_allows_ip_and_unix_sockets_but_blocks_other_families_and_bind() {
    let mut config = common::base();
    config.network = NetworkPolicy::OutboundOnly;
    // Relaxed IPC isolates the network filter for the AF_UNIX probe.
    config.ipc = IpcPolicy::Relaxed;
    assert!(
        allowed(&config, &["socket-inet"]),
        "AF_INET socket creation must be allowed under OutboundOnly"
    );
    assert!(
        allowed(&config, &["socket-unix"]),
        "AF_UNIX socket creation must be allowed under OutboundOnly"
    );
    for probe in ["socket-netlink", "socket-packet", "socket-vsock"] {
        assert!(
            blocked_by_seccomp(&config, &[probe]),
            "{probe} must be blocked under OutboundOnly"
        );
    }
    assert!(
        blocked_by_seccomp(&config, &["tcp-bind"]),
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
fn full_network_and_relaxed_ipc_allow_io_uring_syscalls() {
    if !host_has_io_uring() {
        eprintln!("skipping: io_uring unavailable on this host");
        return;
    }
    let mut config = common::base();
    config.network = NetworkPolicy::Full;
    config.ipc = IpcPolicy::Relaxed;
    for &probe in IO_URING_PROBES {
        assert!(
            allowed(&config, &[probe]),
            "{probe} must be allowed under Full network and Relaxed IPC"
        );
    }
}

#[test]
fn strict_ipc_blocks_io_uring_despite_full_network() {
    if !host_has_io_uring() {
        eprintln!("skipping: io_uring unavailable on this host");
        return;
    }
    // IORING_OP_SOCKET could recreate an AF_UNIX socket without passing the
    // syscall filter, so Strict IPC must keep io_uring at ENOSYS.
    let mut config = common::base();
    config.network = NetworkPolicy::Full;
    config.ipc = IpcPolicy::Strict;
    for &probe in IO_URING_PROBES {
        assert_eq!(
            status(&config, &[probe]).code(),
            Some(3),
            "{probe} must fail with ENOSYS while IPC is Strict"
        );
    }
}
