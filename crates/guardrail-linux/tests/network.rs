#![cfg(target_os = "linux")]

use std::net::{TcpListener, UdpSocket};
use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;

use guardrail_core::{Backend, FsAccess, NetworkPolicy, SandboxCommand, SandboxConfig};
use guardrail_linux::LinuxBackend;

mod common;

fn probe(args: &[&str]) -> SandboxCommand {
    common::probe(args)
}

fn status(config: &SandboxConfig, args: &[&str]) -> ExitStatus {
    let cmd = probe(args);
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
    std::process::Command::new(common::probe_path())
        .arg("io-uring-setup")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
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
fn deny_allows_unix_sockets() {
    let mut config = common::base();
    config.network = NetworkPolicy::Deny;
    assert!(
        allowed(&config, &["socket-unix"]),
        "the network Deny filter must not block host-local AF_UNIX"
    );
}

#[test]
fn outbound_only_allows_ip_and_unix_sockets_but_blocks_other_families_and_tcp_bind() {
    let mut config = common::base();
    config.network = NetworkPolicy::OutboundOnly;
    if let Some(reason) = outbound_unsupported_reason(&config) {
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
        "an explicit TCP bind must be denied by Landlock under OutboundOnly"
    );
}

#[test]
fn outbound_only_allows_unix_bind_listen() {
    let mut config = common::base();
    config.network = NetworkPolicy::OutboundOnly;
    if let Some(reason) = outbound_unsupported_reason(&config) {
        eprintln!("skipping: {reason}");
        return;
    }
    let name = format!("guardrail-outbound-unix-{}", std::process::id());
    assert!(
        allowed(&config, &["unix-bind-listen", &name]),
        "an abstract Unix-domain server must be allowed under OutboundOnly"
    );
}

#[test]
fn outbound_only_keeps_ipv4_and_ipv6_connections() {
    let mut config = common::base();
    config.network = NetworkPolicy::OutboundOnly;
    if let Some(reason) = outbound_unsupported_reason(&config) {
        eprintln!("skipping: {reason}");
        return;
    }

    for (family, bind_address) in [("IPv4", "127.0.0.1:0"), ("IPv6", "[::1]:0")] {
        let listener = TcpListener::bind(bind_address)
            .unwrap_or_else(|e| panic!("bind {family} loopback: {e}"));
        let address = listener.local_addr().expect("listener address").to_string();
        assert!(
            allowed(&config, &["tcp-connect", &address]),
            "an outbound {family} TCP connection must be allowed under OutboundOnly"
        );
    }
}

#[test]
fn outbound_only_preserves_the_unbound_tcp_listener_residual() {
    let mut config = common::base();
    config.network = NetworkPolicy::OutboundOnly;
    if let Some(reason) = outbound_unsupported_reason(&config) {
        eprintln!("skipping: {reason}");
        return;
    }
    assert!(
        allowed(&config, &["tcp-listen-unbound"]),
        "listen on an unbound TCP socket must retain its implicit ephemeral bind"
    );
    assert_eq!(
        status(&config, &["tcp-bind"]).code(),
        Some(3),
        "an explicit TCP bind must still be denied"
    );
}

#[test]
fn outbound_only_udp_bind_is_best_effort_by_exact_abi() {
    let mut config = common::base();
    config.network = NetworkPolicy::OutboundOnly;
    if let Some(reason) = outbound_unsupported_reason(&config) {
        eprintln!("skipping: {reason}");
        return;
    }

    assert!(
        allowed(&config, &["udp-bind", "0"]),
        "an explicit UDP port-0 bind must remain available"
    );

    let port = unused_udp_port().to_string();
    let fixed_allowed = allowed(&config, &["udp-bind", &port]);
    assert_eq!(
        fixed_allowed,
        common::landlock_abi() < 10,
        "fixed UDP bind must be denied only when ABI v10 can mediate it"
    );
}

#[test]
fn outbound_only_network_layer_does_not_narrow_filesystem_refer() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source_dir = dir.path().join("source");
    let destination_dir = dir.path().join("destination");
    std::fs::create_dir(&source_dir).expect("create source directory");
    std::fs::create_dir(&destination_dir).expect("create destination directory");
    let source = source_dir.join("file");
    let destination = destination_dir.join("file");
    std::fs::write(&source, b"data").expect("write source");

    let mut config = common::base();
    config.network = NetworkPolicy::OutboundOnly;
    config.fs.push(FsAccess::WriteAllow(dir.path().into()));
    if let Some(reason) = outbound_unsupported_reason(&config) {
        eprintln!("skipping: {reason}");
        return;
    }

    assert!(
        allowed(
            &config,
            &[
                "rename-file",
                source.to_str().expect("UTF-8 source"),
                destination.to_str().expect("UTF-8 destination"),
            ],
        ),
        "the network-only Landlock layer must preserve cross-directory rename granted by FsAccess"
    );
}

fn unused_udp_port() -> u16 {
    let socket = UdpSocket::bind(("127.0.0.1", 0)).expect("bind temporary UDP socket");
    socket.local_addr().expect("temporary UDP address").port()
}

/// The `Unsupported` reason when the host kernel lacks Landlock ABI v4,
/// which is required to preserve OutboundOnly's explicit TCP-bind guarantee.
#[expect(
    clippy::panic,
    reason = "an unexpected backend error invalidates the test harness"
)]
fn outbound_unsupported_reason(config: &SandboxConfig) -> Option<String> {
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
        if policy == NetworkPolicy::OutboundOnly
            && let Some(reason) = outbound_unsupported_reason(&config)
        {
            eprintln!("skipping OutboundOnly: {reason}");
            continue;
        }
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
fn full_network_allows_io_uring() {
    if !host_has_io_uring() {
        eprintln!("skipping: io_uring unavailable on this host");
        return;
    }
    let mut config = common::base();
    config.network = NetworkPolicy::Full;
    for &probe in IO_URING_PROBES {
        assert!(
            allowed(&config, &[probe]),
            "{probe} must be allowed under Full network"
        );
    }
}
