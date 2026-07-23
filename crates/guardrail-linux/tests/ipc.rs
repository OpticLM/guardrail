#![cfg(target_os = "linux")]

use std::ffi::CString;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::os::fd::AsRawFd;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixDatagram, UnixListener, UnixStream};
use std::process::{Command as StdCommand, ExitStatus, Stdio};
use std::thread;
use std::time::Duration;

use guardrail_core::{Backend, FsAccess, SandboxChild, SandboxCommand, SandboxConfig, StdioMode};
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

struct HostMessageQueue {
    name: CString,
    path: String,
}

impl HostMessageQueue {
    fn new() -> Self {
        let name =
            CString::new(format!("/guardrail-host-mq-{}", std::process::id())).expect("queue name");
        // SAFETY: name is NUL-terminated, the scalar flags request a new
        // queue, and a null attribute pointer selects the system defaults.
        let descriptor = unsafe {
            libc::mq_open(
                name.as_ptr(),
                libc::O_CREAT | libc::O_EXCL | libc::O_RDWR | libc::O_CLOEXEC,
                0o600,
                std::ptr::null::<libc::mq_attr>(),
            )
        };
        assert!(descriptor >= 0, "create host POSIX message queue");
        // SAFETY: descriptor is owned above and no longer needed.
        assert_eq!(unsafe { libc::mq_close(descriptor) }, 0, "close host queue");
        let path = format!(
            "/dev/mqueue/{}",
            name.to_str()
                .expect("UTF-8 queue name")
                .trim_start_matches('/')
        );
        Self { name, path }
    }
}

impl Drop for HostMessageQueue {
    fn drop(&mut self) {
        // SAFETY: name remains NUL-terminated and identifies the queue this
        // helper created. Cleanup is best effort during unwinding.
        unsafe { libc::mq_unlink(self.name.as_ptr()) };
    }
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
fn private_mqueue_is_mounted_for_the_fresh_ipc_namespace() {
    let config = common::base();
    assert!(
        allowed(&config, &["posix-mq"]),
        "POSIX message queues must work through the private /dev/mqueue mount"
    );
}

#[test]
fn private_mqueue_hides_host_queues_even_when_host_path_is_allowed() {
    let host = HostMessageQueue::new();
    let mut config = common::base();
    config.fs.push(FsAccess::ReadAllow("/dev/mqueue".into()));
    assert!(
        !allowed(&config, &["read-file", &host.path]),
        "the private mqueue mount must hide the host queue"
    );
}

#[test]
fn sysv_shared_memory_is_usable_in_the_fresh_namespace() {
    let config = common::base();
    assert!(
        allowed(&config, &["shm"]),
        "SysV shared memory must work inside the fresh IPC namespace"
    );
}

#[test]
fn process_inspection_works_inside_the_sandbox_domain() {
    let config = common::base();
    for probe in ["ptrace-self", "ptrace-child", "process-vm-child"] {
        assert!(
            allowed(&config, &[probe]),
            "{probe} must work within the Landlock domain"
        );
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

    let config = common::base();

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
fn unix_socket_and_socketpair_creation_are_usable() {
    let config = common::base();
    assert!(
        allowed(&config, &["socket-unix"]),
        "creating an AF_UNIX socket must be allowed"
    );
    assert!(
        allowed(&config, &["socketpair-unix"]),
        "connection-oriented Unix socketpair must be allowed"
    );
}

#[test]
fn abstract_host_socket_is_scoped_on_abi_v6_and_newer() {
    let name = format!("guardrail-ipc-relaxed-{}", std::process::id());
    let addr = SocketAddr::from_abstract_name(name.as_bytes()).expect("abstract address");
    let receiver = UnixDatagram::bind_addr(&addr).expect("bind abstract socket");
    let config = common::base();

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
    let config = common::base();

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
fn granted_host_service_can_pass_an_open_file_descriptor() {
    let dir = tempfile::tempdir().expect("tempdir");
    let socket = dir.path().join("host.sock");
    let secret = dir.path().join("secret.txt");
    let expected = "descriptor capability";
    std::fs::write(&secret, expected).expect("write host file");
    let file = File::open(&secret).expect("open host file before sandboxing");
    let listener = UnixListener::bind(&socket).expect("bind host socket");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");

    let mut config = common::base();
    config.linux_unix_sockets.push(socket.clone());
    assert!(
        !allowed(
            &config,
            &["read-file", secret.to_str().expect("UTF-8 path")]
        ),
        "the backing path must remain unavailable through FsAccess"
    );

    let sender = thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    send_fd(&stream, &file);
                    return;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "sandbox did not connect to granted host socket"
                    );
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("accept host socket: {error}"),
            }
        }
    });

    assert!(
        allowed(
            &config,
            &[
                "unix-recv-fd",
                socket.to_str().expect("UTF-8 path"),
                expected,
            ]
        ),
        "a granted service may pass an already-open descriptor independently of FsAccess"
    );
    sender.join().expect("host sender thread");
}

#[expect(
    clippy::multiple_unsafe_ops_per_block,
    reason = "constructing and sending one SCM_RIGHTS control message is one UAPI operation"
)]
fn send_fd(stream: &UnixStream, file: &File) {
    let mut payload = [b'x'];
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: payload.len(),
    };
    // `usize` storage gives cmsghdr its required native alignment.
    let mut control = [0usize; 8];
    // SAFETY: all pointer-bearing fields are initialized below before sendmsg.
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    // SAFETY: CMSG_SPACE computes the buffer size for the scalar payload size.
    message.msg_controllen =
        unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as _) as usize };
    // SAFETY: message's control buffer is live, aligned, and large enough for
    // one descriptor, so its first header and payload are writable.
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        assert!(!header.is_null(), "SCM_RIGHTS header");
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as _) as usize;
        std::ptr::write_unaligned(
            libc::CMSG_DATA(header).cast::<libc::c_int>(),
            file.as_raw_fd(),
        );
        assert_eq!(
            libc::sendmsg(stream.as_raw_fd(), &message, 0),
            1,
            "send SCM_RIGHTS descriptor"
        );
    }
}

#[test]
fn filesystem_access_does_not_grant_host_pathname_socket_connection() {
    let dir = tempfile::tempdir().expect("tempdir");
    let socket = dir.path().join("host.sock");
    let _listener = UnixListener::bind(&socket).expect("bind host socket");
    let mut config = common::base();
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
    let config = common::base();

    assert!(
        allowed(&config, &["unix-path-roundtrip", &path]),
        "ABI v9 pathname mediation must not block a server created within the same Landlock domain"
    );
}

#[test]
fn same_domain_abstract_socket_remains_usable() {
    let name = format!("guardrail-same-domain-{}", std::process::id());
    let config = common::base();

    assert!(
        allowed(&config, &["unix-abstract-roundtrip", &name]),
        "ABI v6 abstract-socket scoping must preserve servers created within the same Landlock domain"
    );
}

#[test]
fn host_signal_is_scoped_on_abi_v6_and_newer() {
    let config = common::base();
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
    let config = common::base();

    assert!(
        allowed(&config, &["signal-child-zero"]),
        "signal permission checks for a child in the same Landlock domain must remain available"
    );
}
