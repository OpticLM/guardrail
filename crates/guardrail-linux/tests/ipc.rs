#![cfg(target_os = "linux")]

use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixDatagram};
use std::process::ExitStatus;
use std::time::Duration;

use guardrail_core::{
    Backend, FsAccess, IpcPolicy, NetworkPolicy, SandboxChild, SandboxCommand, SandboxConfig,
    StdioMode,
};
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

fn spawn_output(backend: &LinuxBackend, args: &[&str]) -> SandboxChild {
    let mut command = probe(args);
    command.stdout = StdioMode::Piped;
    backend.spawn(command).expect("spawn")
}

fn wait_output(child: SandboxChild) -> String {
    let output = child.wait_with_output().expect("wait with output");
    assert!(output.status.success(), "probe must succeed");
    String::from_utf8(output.stdout).expect("probe output must be UTF-8")
}

#[test]
fn every_spawn_gets_a_fresh_ipc_namespace() {
    let backend = LinuxBackend::new(common::base()).expect("backend");
    let host = std::fs::read_link("/proc/self/ns/ipc")
        .expect("host IPC namespace")
        .to_string_lossy()
        .into_owned();
    // Both children hold their namespaces for 500 ms, and both are spawned
    // before either is waited. Their namespace inodes therefore coexist and
    // cannot be legally recycled between the two observations.
    let mut first_child = spawn_output(&backend, &["ipc-namespace", "500"]);
    let second_child = spawn_output(&backend, &["ipc-namespace", "500"]);
    assert!(
        first_child
            .as_child_mut()
            .expect("Linux child")
            .try_wait()
            .expect("poll first child")
            .is_none(),
        "first namespace must still exist after the second spawn"
    );
    let first = wait_output(first_child);
    let second = wait_output(second_child);

    assert_ne!(first, host, "sandbox must not share the host IPC namespace");
    assert_ne!(
        second, host,
        "sandbox must not share the host IPC namespace"
    );
    assert_ne!(first, second, "each spawn must get its own IPC namespace");
}

#[test]
fn private_shm_is_bounded_hardened_and_usable() {
    let config = common::base();
    assert!(
        allowed(&config, &["private-shm-mount"]),
        "/dev/shm must be a <=64 MiB nosuid,nodev,noexec tmpfs"
    );
    assert!(
        allowed(&config, &["posix-shm"]),
        "POSIX shared memory must work inside the private /dev/shm"
    );
}

#[test]
fn private_shm_hides_host_objects_even_when_host_path_is_allowed() {
    let host_dir = tempfile::tempdir_in("/dev/shm").expect("host /dev/shm tempdir");
    let marker = host_dir.path().join("host-marker");
    std::fs::write(&marker, b"host").expect("write host marker");

    let mut config = common::base();
    config.fs.push(FsAccess::ReadAllow("/dev/shm".into()));
    assert!(
        !allowed(
            &config,
            &["read-file", marker.to_str().expect("UTF-8 path")]
        ),
        "the private mount must hide host /dev/shm even when its host path was granted"
    );
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
