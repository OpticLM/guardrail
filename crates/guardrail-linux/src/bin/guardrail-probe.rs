//! Test helper exercised by guardrail-linux integration tests.
//!
//! Usage: `guardrail-probe <COMMAND> [ARG]`
//!
//! Exit codes:
//!   0   operation succeeded / allowed
//!   3   operation failed because it was denied (the expected sandboxed result)
//!   2   usage or probe error
//!
//! Commands:
//!   echo-env <NAME>   print the value of env var NAME (empty if unset), exit 0
//!   alloc <MB>        try to allocate and touch <MB> megabytes; exit 0 if it
//!                     succeeds, exit 3 if allocation fails
//!   spin              busy-loop forever (for CPU-time-limit tests)
//!   fork              fork one child that exits immediately; exit 0 if the
//!                     fork succeeds, exit 3 if it is denied
//!   read-file <PATH>  read PATH; exit 0 if allowed, exit 3 if denied/failed
//!   wait-read-file <PATH> <SECONDS>
//!                     poll until PATH exists (up to SECONDS), then read it;
//!                     exit 0 if the read succeeds, 3 if it is denied or the
//!                     path never appears
//!   write-file <PATH> write one byte to PATH; exit 0 if allowed, 3 if denied
//!   rename-file <SRC> <DST>
//!                     rename SRC to DST; exit 0 if allowed, 3 if denied
//!   link-file <SRC> <DST>
//!                     hard-link SRC to DST; exit 0 if allowed, 3 if denied
//!   read-fd <FD> <EXPECTED>
//!                     read from the (supposedly inherited) descriptor FD;
//!                     exit 0 if it yields EXPECTED, 3 if the read fails or
//!                     the content differs
//!   socket-inet       create an AF_INET TCP socket; exit 0 if allowed, 3 if denied
//!   socket-netlink    create an AF_NETLINK route socket; exit 0 if allowed, 3 if denied
//!   socket-packet     create an AF_PACKET raw socket; exit 0 if allowed, 3 if denied
//!   socket-vsock      create an AF_VSOCK stream socket; exit 0 if allowed, 3 if denied
//!   socket-unix       create an AF_UNIX stream socket; exit 0 if allowed, 3 if denied
//!   socketpair-unix   create a connected AF_UNIX socketpair; exit 0 if
//!                     allowed, 3 if denied
//!   socketpair-unix-dgram-sendto <NAME>
//!                     create an AF_UNIX datagram socketpair and send to the
//!                     abstract socket NAME; exit 0 if allowed, 3 if denied
//!   tcp-bind          bind a TCP listener on 127.0.0.1:0; exit 0 if allowed,
//!                     3 if denied
//!   tcp-connect <ADDR>
//!                     connect a TCP stream to ADDR; exit 0 if allowed, 3 if denied
//!   unix-bind-listen <NAME>
//!                     bind an AF_UNIX stream socket to the abstract name NAME
//!                     and listen on it; exit 0 if allowed, 3 if denied
//!   io-uring-setup    create an io_uring instance; exit 0 if allowed, 3 on ENOSYS
//!   io-uring-enter    call io_uring_enter with an invalid fd; exit 0 if the
//!                     kernel returns EBADF, 3 on ENOSYS
//!   io-uring-register call io_uring_register with invalid arguments; exit 0
//!                     if the kernel returns EINVAL, 3 on ENOSYS
//!   shm               create a SysV shared-memory segment; exit 0 if allowed,
//!                     3 if denied
//!   ptrace-self       call ptrace(PTRACE_TRACEME); exit 0 if allowed, 3 if denied
//!   unshare-user      call unshare(CLONE_NEWUSER); exit 0 if allowed, 3 if denied
//!   mount             call mount(2) with unprivileged-safe arguments; exit 0
//!                     if the syscall reaches the kernel (any errno), never
//!                     returns under the sandbox (SIGSYS)
//!   mount-setattr     call mount_setattr(2) with inert arguments; exit 0 if
//!                     the syscall reaches the kernel (any errno), never
//!                     returns under the sandbox (SIGSYS)
//!   kexec-load        call kexec_load(2) with null arguments; exit 0 if the
//!                     syscall reaches the kernel (any errno), never returns
//!                     under the sandbox (SIGSYS)
//!   bpf               call bpf(2); exit 0 if the syscall reaches the kernel,
//!                     3 if denied with EPERM

#[cfg(target_os = "linux")]
fn main() {
    use std::process::exit;

    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("");
    match cmd {
        "echo-env" => {
            let name = args.get(2).map(String::as_str).unwrap_or("");
            print!("{}", std::env::var(name).unwrap_or_default());
            exit(0);
        }
        "alloc" => {
            let mb: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
            // Allocate and touch every page so the kernel actually commits it.
            let mut v: Vec<u8> = Vec::new();
            if v.try_reserve(mb * 1024 * 1024).is_err() {
                exit(3);
            }
            v.resize(mb * 1024 * 1024, 0);
            let mut acc: u8 = 0;
            let mut i = 0;
            #[expect(
                clippy::indexing_slicing,
                reason = "`i` is checked to be within `0..v.len()`"
            )]
            while i < v.len() {
                v[i] = 1;
                acc = acc.wrapping_add(v[i]);
                i += 4096;
            }
            // Use `acc` so the loop isn't optimized away.
            if acc == 123 {
                eprintln!("unreachable {acc}");
            }
            exit(0);
        }
        "spin" => loop {
            std::hint::spin_loop();
        },
        "fork" => {
            // SAFETY: fork takes no arguments; the child calls only the
            // async-signal-safe `_exit`.
            let pid = unsafe { libc::fork() };
            if pid < 0 {
                exit(3);
            }
            if pid == 0 {
                // SAFETY: immediate exit without running any Rust cleanup.
                unsafe { libc::_exit(0) };
            }
            let mut status: libc::c_int = 0;
            // SAFETY: `status` is a valid out-pointer; pid is our child.
            if unsafe { libc::waitpid(pid, &mut status, 0) } < 0 {
                exit(2);
            }
            exit(0);
        }
        "read-file" => {
            let path = args.get(2).map(String::as_str).unwrap_or("");
            match std::fs::read(path) {
                Ok(_) => exit(0),
                Err(_) => exit(3),
            }
        }
        "wait-read-file" => {
            let path = args.get(2).map(String::as_str).unwrap_or("");
            let Some(seconds) = args.get(3).and_then(|s| s.parse::<u64>().ok()) else {
                exit(2);
            };
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(seconds);
            loop {
                match std::fs::read(path) {
                    Ok(_) => exit(0),
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                        if std::time::Instant::now() >= deadline {
                            exit(3);
                        }
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(_) => exit(3),
                }
            }
        }
        "write-file" => {
            let path = args.get(2).map(String::as_str).unwrap_or("");
            match std::fs::write(path, b"x") {
                Ok(_) => exit(0),
                Err(_) => exit(3),
            }
        }
        "rename-file" => {
            let (Some(src), Some(dst)) = (args.get(2), args.get(3)) else {
                exit(2);
            };
            match std::fs::rename(src, dst) {
                Ok(()) => exit(0),
                Err(_) => exit(3),
            }
        }
        "link-file" => {
            let (Some(src), Some(dst)) = (args.get(2), args.get(3)) else {
                exit(2);
            };
            match std::fs::hard_link(src, dst) {
                Ok(()) => exit(0),
                Err(_) => exit(3),
            }
        }
        "read-fd" => {
            let Some(fd) = args.get(2).and_then(|s| s.parse::<libc::c_int>().ok()) else {
                exit(2);
            };
            let Some(expected) = args.get(3) else {
                exit(2);
            };
            // One extra byte so trailing content beyond EXPECTED is detected.
            let mut buf = vec![0u8; expected.len() + 1];
            // SAFETY: buf is a valid writable buffer of the given length.
            let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
            if n < 0 {
                exit(3);
            }
            if buf.get(..n.cast_unsigned() as usize) == Some(expected.as_bytes()) {
                exit(0);
            }
            exit(3);
        }
        "socket-inet" => exit_socket_probe(libc::AF_INET, libc::SOCK_STREAM, 0),
        "socket-netlink" => {
            exit_socket_probe(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE)
        }
        "socket-packet" => {
            let protocol = libc::htons(libc::ETH_P_ALL as u16) as libc::c_int;
            exit_socket_probe(libc::AF_PACKET, libc::SOCK_RAW, protocol);
        }
        "socket-vsock" => exit_socket_probe(libc::AF_VSOCK, libc::SOCK_STREAM, 0),
        "socket-unix" => exit_socket_probe(libc::AF_UNIX, libc::SOCK_STREAM, 0),
        "socketpair-unix" => {
            let mut fds = [-1 as libc::c_int; 2];
            // SAFETY: socketpair writes the two descriptors into `fds`.
            let rc =
                unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
            if rc < 0 {
                exit(3);
            }
            // SAFETY: both fds were created above and are owned here.
            unsafe {
                libc::close(fds[0]);
            }
            // SAFETY: both fds were created above and are owned here.
            unsafe {
                libc::close(fds[1]);
            }
            exit(0);
        }
        "socketpair-unix-dgram-sendto" => {
            use std::os::linux::net::SocketAddrExt;
            use std::os::unix::net::{SocketAddr, UnixDatagram};

            let Some(name) = args.get(2) else {
                exit(2);
            };
            let Ok(addr) = SocketAddr::from_abstract_name(name.as_bytes()) else {
                exit(2);
            };
            let Ok((socket, _peer)) = UnixDatagram::pair() else {
                exit(3);
            };
            match socket.send_to_addr(b"x", &addr) {
                Ok(_) => exit(0),
                Err(_) => exit(3),
            }
        }
        "tcp-bind" => match std::net::TcpListener::bind(("127.0.0.1", 0)) {
            Ok(_) => exit(0),
            Err(_) => exit(3),
        },
        "tcp-connect" => {
            let Some(address) = args.get(2) else {
                exit(2);
            };
            match std::net::TcpStream::connect(address) {
                Ok(_) => exit(0),
                Err(_) => exit(3),
            }
        }
        "unix-bind-listen" => {
            use std::os::linux::net::SocketAddrExt;
            use std::os::unix::net::{SocketAddr, UnixListener};

            let Some(name) = args.get(2) else {
                exit(2);
            };
            let Ok(addr) = SocketAddr::from_abstract_name(name.as_bytes()) else {
                exit(2);
            };
            match UnixListener::bind_addr(&addr) {
                Ok(_) => exit(0),
                Err(_) => exit(3),
            }
        }
        "io-uring-setup" => {
            // io_uring_setup(2) has no libc wrapper; a zeroed params block
            // requests no optional features. [0u64; 15] matches struct
            // io_uring_params' 120-byte size and 8-byte alignment.
            let mut params = [0u64; 15];
            // SAFETY: params is a valid, writable, zeroed buffer the kernel
            // fills in; it outlives the call.
            let fd = unsafe {
                libc::syscall(
                    libc::SYS_io_uring_setup,
                    4 as libc::c_long,
                    params.as_mut_ptr(),
                )
            };
            if fd < 0 {
                exit_io_uring_probe_error(None);
            }
            // SAFETY: fd was returned by io_uring_setup above and is owned here.
            unsafe { libc::close(fd as libc::c_int) };
            exit(0);
        }
        "io-uring-enter" => {
            // An invalid fd proves that the syscall reached the kernel when
            // it returns EBADF; the sandbox replaces that result with ENOSYS.
            // SAFETY: the invalid fd is intentional and all pointer lengths
            // are zero, so the kernel does not dereference the null pointer.
            let rc = unsafe {
                libc::syscall(
                    libc::SYS_io_uring_enter,
                    -1 as libc::c_long,
                    0 as libc::c_long,
                    0 as libc::c_long,
                    0 as libc::c_long,
                    std::ptr::null::<libc::sigset_t>(),
                    0 as libc::c_long,
                )
            };
            if rc < 0 {
                exit_io_uring_probe_error(Some(libc::EBADF));
            }
            exit(0);
        }
        "io-uring-register" => {
            // IORING_REGISTER_BUFFERS with zero buffers reaches the syscall
            // and deterministically returns EINVAL when it is allowed.
            // SAFETY: zero arguments mean the kernel does not dereference the
            // null pointer.
            let rc = unsafe {
                libc::syscall(
                    libc::SYS_io_uring_register,
                    -1 as libc::c_long,
                    0 as libc::c_long,
                    std::ptr::null::<libc::c_void>(),
                    0 as libc::c_long,
                )
            };
            if rc < 0 {
                exit_io_uring_probe_error(Some(libc::EINVAL));
            }
            exit(0);
        }
        "shm" => {
            // SAFETY: shmget with scalar args. IPC_PRIVATE creates a new segment.
            let id = unsafe { libc::shmget(libc::IPC_PRIVATE, 4096, libc::IPC_CREAT | 0o600) };
            if id < 0 {
                exit(3);
            }
            // SAFETY: id was created above; cleanup is best effort.
            unsafe { libc::shmctl(id, libc::IPC_RMID, std::ptr::null_mut()) };
            exit(0);
        }
        "ptrace-self" => {
            // SAFETY: ptrace TRACEME takes no pointer args.
            let rc = unsafe {
                libc::ptrace(
                    libc::PTRACE_TRACEME,
                    0,
                    std::ptr::null_mut::<libc::c_void>(),
                    std::ptr::null_mut::<libc::c_void>(),
                )
            };
            if rc < 0 {
                exit(3);
            } else {
                exit(0);
            }
        }
        "unshare-user" => {
            // SAFETY: unshare takes only a scalar flags argument.
            let rc = unsafe { libc::unshare(libc::CLONE_NEWUSER) };
            if rc == 0 { exit(0) } else { exit(3) }
        }
        "mount" => {
            // Unprivileged-safe: outside a sandbox this fails with EPERM (or
            // ENOENT) without mounting anything. Any returned errno proves the
            // syscall reached the kernel; the sandbox's Trap never returns.
            // SAFETY: all pointers are valid NUL-terminated strings.
            unsafe {
                libc::mount(
                    c"none".as_ptr(),
                    c"/nonexistent-guardrail-probe".as_ptr(),
                    c"tmpfs".as_ptr(),
                    0,
                    std::ptr::null(),
                )
            };
            exit(0);
        }
        "mount-setattr" => {
            // A zeroed attribute structure requests no changes, and the path
            // does not exist. Any returned errno proves the syscall reached
            // the kernel; the sandbox's Trap never returns.
            let attr = libc::mount_attr {
                attr_set: 0,
                attr_clr: 0,
                propagation: 0,
                userns_fd: 0,
            };
            // SAFETY: the path and attribute pointers are valid for the
            // lengths passed, and the inert request cannot change mount state.
            unsafe {
                libc::syscall(
                    libc::SYS_mount_setattr,
                    libc::AT_FDCWD,
                    c"/nonexistent-guardrail-probe".as_ptr(),
                    0 as libc::c_uint,
                    &attr,
                    std::mem::size_of_val(&attr),
                )
            };
            exit(0);
        }
        "kexec-load" => {
            // Zero segments and null pointers: outside a sandbox this fails
            // with EPERM without CAP_SYS_BOOT. Reaching the kernel at all
            // (any errno) means the syscall was not trapped.
            // SAFETY: zero counts mean the kernel dereferences no pointers.
            unsafe {
                libc::syscall(
                    libc::SYS_kexec_load,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                    std::ptr::null::<libc::c_void>(),
                    0 as libc::c_ulong,
                )
            };
            exit(0);
        }
        "bpf" => {
            // Command 0 (BPF_MAP_CREATE) with a null attr pointer: never
            // creates anything. EPERM = denied (sandbox filter, or a host with
            // kernel.unprivileged_bpf_disabled); other errnos (EINVAL, EFAULT)
            // prove the syscall reached the kernel.
            // SAFETY: a null attr pointer is rejected by the kernel, not
            // dereferenced blindly.
            let rc = unsafe {
                libc::syscall(
                    libc::SYS_bpf,
                    0 as libc::c_int,
                    std::ptr::null::<libc::c_void>(),
                    0 as libc::c_uint,
                )
            };
            if rc < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM) {
                exit(3);
            }
            exit(0);
        }
        _ => {
            eprintln!(
                "usage: guardrail-probe \
                 <echo-env|alloc|spin|fork|read-file|wait-read-file|write-file|\
                 rename-file|link-file|read-fd|\
                 socket-inet|socket-netlink|socket-packet|socket-vsock|socket-unix|\
                 socketpair-unix|socketpair-unix-dgram-sendto|tcp-bind|tcp-connect|\
                 unix-bind-listen|io-uring-setup|io-uring-enter|io-uring-register|shm|\
                 ptrace-self|unshare-user|mount|mount-setattr|kexec-load|bpf> [arg]"
            );
            exit(2);
        }
    }
}

#[cfg(target_os = "linux")]
fn exit_socket_probe(domain: libc::c_int, socket_type: libc::c_int, protocol: libc::c_int) -> ! {
    use std::process::exit;

    // SAFETY: socket() takes scalar args; close the fd if created.
    let fd = unsafe { libc::socket(domain, socket_type, protocol) };
    if fd < 0 {
        exit(3);
    }
    // SAFETY: fd was returned by socket() above and is owned here.
    unsafe { libc::close(fd) };
    exit(0);
}

#[cfg(target_os = "linux")]
fn exit_io_uring_probe_error(allowed_errno: Option<libc::c_int>) -> ! {
    use std::process::exit;

    let error = std::io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ENOSYS) => exit(3),
        Some(errno) if allowed_errno == Some(errno) => exit(0),
        _ => {
            eprintln!("unexpected io_uring error: {error}");
            exit(2);
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {}
