#![cfg(target_os = "linux")]

use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixDatagram};
use std::process::ExitStatus;
use std::time::Duration;

use guardrail_core::{Backend, IpcPolicy, NetworkPolicy, SandboxCommand, SandboxConfig};
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

#[test]
fn strict_blocks_shared_memory() {
    let mut config = common::base();
    config.linux_ipc = IpcPolicy::Strict;
    assert!(
        !allowed(&config, &["shm"]),
        "SysV shared memory must be blocked under Strict IPC"
    );
}

#[test]
fn relaxed_allows_shared_memory() {
    let mut config = common::base();
    config.linux_ipc = IpcPolicy::Relaxed;
    assert!(
        allowed(&config, &["shm"]),
        "shared memory must be allowed under Relaxed IPC"
    );
}

#[test]
fn ptrace_is_blocked_at_both_levels() {
    for level in [IpcPolicy::Strict, IpcPolicy::Relaxed] {
        let mut config = common::base();
        config.linux_ipc = level;
        assert!(
            !allowed(&config, &["ptrace-self"]),
            "ptrace must be blocked under {level:?} IPC"
        );
    }
}

#[test]
fn strict_blocks_unix_socket_creation_with_a_graceful_errno() {
    let mut config = common::base();
    config.linux_ipc = IpcPolicy::Strict;
    // Exit 3, not SIGSYS: the denial is Errno(EAFNOSUPPORT) so tools probing
    // optional local sockets fall back instead of dying.
    assert_eq!(
        status(&config, &["socket-unix"]).code(),
        Some(3),
        "creating an AF_UNIX socket must fail with an errno under Strict IPC"
    );
}

#[test]
fn strict_blocks_unix_socket_creation_even_with_full_network() {
    let mut config = common::base();
    config.network = NetworkPolicy::Full;
    config.linux_ipc = IpcPolicy::Strict;
    assert_eq!(
        status(&config, &["socket-unix"]).code(),
        Some(3),
        "Strict IPC must deny AF_UNIX regardless of the network policy"
    );
}

#[test]
fn relaxed_allows_unix_socket_creation() {
    let mut config = common::base();
    config.linux_ipc = IpcPolicy::Relaxed;
    assert!(
        allowed(&config, &["socket-unix"]),
        "creating an AF_UNIX socket must be allowed under Relaxed IPC"
    );
}

#[test]
fn strict_allows_unix_socketpair() {
    let mut config = common::base();
    config.linux_ipc = IpcPolicy::Strict;
    assert!(
        allowed(&config, &["socketpair-unix"]),
        "socketpair must stay available under Strict IPC"
    );
}

#[test]
fn strict_blocks_unix_datagram_socketpair_escape() {
    let name = format!("guardrail-ipc-strict-{}", std::process::id());
    let addr = SocketAddr::from_abstract_name(name.as_bytes()).expect("abstract address");
    let _receiver = UnixDatagram::bind_addr(&addr).expect("bind abstract socket");
    let mut config = common::base();
    config.linux_ipc = IpcPolicy::Strict;

    assert_eq!(
        status(&config, &["socketpair-unix-dgram-sendto", &name]).code(),
        Some(3),
        "Strict IPC must block datagram socketpairs that can target named sockets"
    );
}

#[test]
fn relaxed_allows_unix_datagram_socketpair_sendto() {
    let name = format!("guardrail-ipc-relaxed-{}", std::process::id());
    let addr = SocketAddr::from_abstract_name(name.as_bytes()).expect("abstract address");
    let receiver = UnixDatagram::bind_addr(&addr).expect("bind abstract socket");
    let mut config = common::base();
    config.linux_ipc = IpcPolicy::Relaxed;

    assert!(
        allowed(&config, &["socketpair-unix-dgram-sendto", &name]),
        "Relaxed IPC must allow datagram socketpairs to target named sockets"
    );
    receiver
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("set receive timeout");
    let mut byte = [0];
    assert_eq!(receiver.recv(&mut byte).expect("receive datagram"), 1);
    assert_eq!(byte, *b"x");
}

#[test]
fn default_ipc_is_strict() {
    // The default must be Strict (matches guardrail-core's default).
    let config = common::base();
    assert!(
        !allowed(&config, &["shm"]),
        "default IPC level must behave as Strict (shm blocked)"
    );
    assert_eq!(
        status(&config, &["socket-unix"]).code(),
        Some(3),
        "default IPC level must behave as Strict (AF_UNIX blocked)"
    );
}
