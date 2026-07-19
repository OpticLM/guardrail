#![cfg(target_os = "linux")]

use std::net::TcpListener;
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
    config.linux_ipc = IpcPolicy::Relaxed;
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
    config.linux_ipc = IpcPolicy::Relaxed;
    if let Some(reason) = outbound_relaxed_unsupported_reason(&config) {
        eprintln!("skipping: {reason}");
        return;
    }
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
    // Exit 3, not SIGSYS: the denial is Landlock's EACCES, family-aware so
    // Unix-domain servers stay available (see below).
    assert_eq!(
        status(&config, &["tcp-bind"]).code(),
        Some(3),
        "binding a TCP listener must be denied under OutboundOnly with Relaxed IPC"
    );
}

#[test]
fn outbound_only_with_relaxed_ipc_allows_unix_bind_listen() {
    let mut config = common::base();
    config.network = NetworkPolicy::OutboundOnly;
    config.linux_ipc = IpcPolicy::Relaxed;
    if let Some(reason) = outbound_relaxed_unsupported_reason(&config) {
        eprintln!("skipping: {reason}");
        return;
    }
    let name = format!("guardrail-outbound-unix-{}", std::process::id());
    assert!(
        allowed(&config, &["unix-bind-listen", &name]),
        "an abstract Unix-domain server must be allowed under OutboundOnly with Relaxed IPC"
    );
}

#[test]
fn outbound_only_with_relaxed_ipc_keeps_ipv4_and_ipv6_connections() {
    let mut config = common::base();
    config.network = NetworkPolicy::OutboundOnly;
    config.linux_ipc = IpcPolicy::Relaxed;
    if let Some(reason) = outbound_relaxed_unsupported_reason(&config) {
        eprintln!("skipping: {reason}");
        return;
    }

    for (family, bind_address) in [("IPv4", "127.0.0.1:0"), ("IPv6", "[::1]:0")] {
        let listener = TcpListener::bind(bind_address)
            .unwrap_or_else(|e| panic!("bind {family} loopback: {e}"));
        let address = listener.local_addr().expect("listener address").to_string();
        assert!(
            allowed(&config, &["tcp-connect", &address]),
            "an outbound {family} TCP connection must be allowed under OutboundOnly with Relaxed IPC"
        );
    }
}

#[test]
fn outbound_only_with_strict_ipc_keeps_trapping_bind() {
    let mut config = common::base();
    config.network = NetworkPolicy::OutboundOnly;
    config.linux_ipc = IpcPolicy::Strict;
    // With no Unix-domain sockets creatable, the family-blind whole-syscall
    // traps stay sound and keep the harder SIGSYS denial.
    assert!(
        blocked_by_seccomp(&config, &["tcp-bind"]),
        "binding/listening must be trapped under OutboundOnly with Strict IPC"
    );
}

/// The `Unsupported` reason when the host kernel lacks the Landlock network
/// support (ABI v4) that OutboundOnly + Relaxed IPC requires, so tests can
/// skip with it.
fn outbound_relaxed_unsupported_reason(config: &SandboxConfig) -> Option<String> {
    match LinuxBackend::new(config.clone()) {
        Ok(_) => None,
        Err(guardrail_core::Error::Unsupported(reason)) => Some(reason),
        Err(other) => panic!("unexpected backend error: {other:?}"),
    }
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
    config.linux_ipc = IpcPolicy::Relaxed;
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
    config.linux_ipc = IpcPolicy::Strict;
    for &probe in IO_URING_PROBES {
        assert_eq!(
            status(&config, &[probe]).code(),
            Some(3),
            "{probe} must fail with ENOSYS while IPC is Strict"
        );
    }
}
