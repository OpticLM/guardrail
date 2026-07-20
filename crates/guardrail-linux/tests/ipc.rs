#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader};
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixDatagram, UnixListener};
use std::process::{Command as StdCommand, ExitStatus, Stdio};
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
fn process_inspection_works_inside_the_sandbox_domain() {
    for level in [IpcPolicy::Strict, IpcPolicy::Relaxed] {
        let mut config = common::base();
        config.linux_ipc = level;
        for probe in ["ptrace-self", "ptrace-child", "process-vm-child"] {
            assert!(
                allowed(&config, &[probe]),
                "{probe} must work within the Landlock domain under {level:?} IPC"
            );
        }
    }
}

#[test]
fn process_inspection_cannot_reach_the_host_domain() {
    let mut target = StdCommand::new(common::probe_path())
        .arg("process-vm-target")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn opted-in host target");
    let mut published = String::new();
    BufReader::new(target.stdout.take().expect("target stdout"))
        .read_line(&mut published)
        .expect("read target marker");
    let fields: Vec<_> = published.split_whitespace().collect();
    assert_eq!(fields.len(), 3, "target must publish pid, address, value");

    let baseline = StdCommand::new(common::probe_path())
        .args(["process-vm-host", fields[0], fields[1], fields[2]])
        .status()
        .expect("run unsandboxed reader");
    if !baseline.success() {
        eprintln!(
            "skipping host-domain process inspection: ordinary unsandboxed access is unavailable"
        );
        drop(target.stdin.take());
        assert!(target.wait().expect("wait host target").success());
        return;
    }

    let mut config = common::base();
    config.linux_ipc = IpcPolicy::Relaxed;

    assert!(
        !allowed(
            &config,
            &["process-vm-host", fields[0], fields[1], fields[2]]
        ),
        "Landlock's implicit ptrace hierarchy must deny process_vm_readv from the sandbox domain into its host parent domain"
    );

    drop(target.stdin.take());
    assert!(target.wait().expect("wait host target").success());
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
fn abstract_host_socket_is_scoped_on_abi_v6_and_newer() {
    let name = format!("guardrail-ipc-relaxed-{}", std::process::id());
    let addr = SocketAddr::from_abstract_name(name.as_bytes()).expect("abstract address");
    let receiver = UnixDatagram::bind_addr(&addr).expect("bind abstract socket");
    let mut config = common::base();
    config.linux_ipc = IpcPolicy::Relaxed;

    let sent = allowed(&config, &["socketpair-unix-dgram-sendto", &name]);
    if common::landlock_abi() >= 6 {
        assert!(
            !sent,
            "ABI v6+ must deny sends to host-created abstract sockets"
        );
    } else {
        assert!(
            sent,
            "ABI before v6 must leave abstract sockets unrestricted"
        );
        receiver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("set receive timeout");
        let mut byte = [0];
        assert_eq!(receiver.recv(&mut byte).expect("receive datagram"), 1);
        assert_eq!(byte, *b"x");
    }
}

#[test]
fn host_pathname_socket_is_denied_by_default_on_abi_v9_and_newer() {
    let dir = tempfile::tempdir().expect("tempdir");
    let socket = dir.path().join("host.sock");
    let _listener = UnixListener::bind(&socket).expect("bind host socket");
    let mut config = common::base();
    config.linux_ipc = IpcPolicy::Relaxed;

    let connected = allowed(
        &config,
        &["unix-connect", socket.to_str().expect("UTF-8 path")],
    );
    assert_eq!(
        connected,
        common::landlock_abi() < 9,
        "host pathname sockets must be denied by default only when ABI v9 can mediate them"
    );
}

#[test]
fn explicit_pathname_socket_grant_allows_host_connection_on_abi_v9_and_newer() {
    let dir = tempfile::tempdir().expect("tempdir");
    let socket = dir.path().join("host.sock");
    let _listener = UnixListener::bind(&socket).expect("bind host socket");
    let mut config = common::base();
    config.linux_ipc = IpcPolicy::Relaxed;
    config.linux_unix_sockets.push(socket.clone());

    assert!(
        allowed(
            &config,
            &["unix-connect", socket.to_str().expect("UTF-8 path")]
        ),
        "an explicit socket grant must allow the host connection; before ABI v9 the field is an ignored no-op"
    );
}

#[test]
fn filesystem_access_does_not_grant_host_pathname_socket_connection() {
    let dir = tempfile::tempdir().expect("tempdir");
    let socket = dir.path().join("host.sock");
    let _listener = UnixListener::bind(&socket).expect("bind host socket");
    let mut config = common::base();
    config.linux_ipc = IpcPolicy::Relaxed;
    config.fs.extend([
        FsAccess::ReadAllow(dir.path().into()),
        FsAccess::WriteAllow(dir.path().into()),
    ]);

    let connected = allowed(
        &config,
        &["unix-connect", socket.to_str().expect("UTF-8 path")],
    );
    assert_eq!(
        connected,
        common::landlock_abi() < 9,
        "FsAccess alone must not grant socket resolution on ABI v9+"
    );
}

#[test]
fn same_domain_pathname_socket_remains_usable() {
    let path = format!("/dev/shm/guardrail-same-domain-{}.sock", std::process::id());
    let mut config = common::base();
    config.linux_ipc = IpcPolicy::Relaxed;

    assert!(
        allowed(&config, &["unix-path-roundtrip", &path]),
        "ABI v9 pathname mediation must not block a server created within the same Landlock domain"
    );
}

#[test]
fn same_domain_abstract_socket_remains_usable() {
    let name = format!("guardrail-same-domain-{}", std::process::id());
    let mut config = common::base();
    config.linux_ipc = IpcPolicy::Relaxed;

    assert!(
        allowed(&config, &["unix-abstract-roundtrip", &name]),
        "ABI v6 abstract-socket scoping must preserve servers created within the same Landlock domain"
    );
}

#[test]
fn host_signal_is_scoped_on_abi_v6_and_newer() {
    let mut config = common::base();
    config.linux_ipc = IpcPolicy::Relaxed;
    let host_pid = std::process::id().to_string();

    let permitted = allowed(&config, &["signal-zero", &host_pid]);
    assert_eq!(
        permitted,
        common::landlock_abi() < 6,
        "ABI v6+ must deny signal permission checks outside the sandbox domain; older ABIs must leave them unrestricted"
    );
}

#[test]
fn same_domain_signal_remains_usable() {
    let mut config = common::base();
    config.linux_ipc = IpcPolicy::Relaxed;

    assert!(
        allowed(&config, &["signal-child-zero"]),
        "signal permission checks for a child in the same Landlock domain must remain available"
    );
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
