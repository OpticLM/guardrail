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
//!   tcp-listen-unbound
//!                     listen on an unbound TCP socket; exit 0 if the kernel
//!                     implicitly assigns a port, 3 if denied
//!   udp-bind PORT     bind a UDP socket on 127.0.0.1:PORT; exit 0 if allowed,
//!                     3 if denied
//!   tcp-connect <ADDR>
//!                     connect a TCP stream to ADDR; exit 0 if allowed, 3 if denied
//!   unix-bind-listen <NAME>
//!                     bind an AF_UNIX stream socket to the abstract name NAME
//!                     and listen on it; exit 0 if allowed, 3 if denied
//!   unix-connect <PATH>
//!                     connect to a pathname AF_UNIX stream server; exit 0 if
//!                     allowed, 3 if denied
//!   unix-recv-fd <PATH> <EXPECTED>
//!                     connect to a pathname AF_UNIX stream server, receive a
//!                     descriptor with SCM_RIGHTS, and read EXPECTED from it;
//!                     exit 0 on success, 3 otherwise
//!   unix-path-roundtrip <PATH>
//!                     bind and connect to a pathname AF_UNIX stream server;
//!                     exit 0 if same-domain use works, 3 otherwise
//!   unix-abstract-roundtrip <NAME>
//!                     bind and connect to an abstract AF_UNIX stream server;
//!                     exit 0 if same-domain use works, 3 otherwise
//!   signal-zero <PID> check permission to signal PID without delivering a
//!                     signal; exit 0 if allowed, 3 if denied
//!   signal-child-zero fork a child and check permission to signal it without
//!                     delivering a signal; exit 0 if allowed, 3 if denied
//!   io-uring-setup    create an io_uring instance; exit 0 if allowed, 3 on ENOSYS
//!   io-uring-enter    call io_uring_enter with an invalid fd; exit 0 if the
//!                     kernel returns EBADF, 3 on ENOSYS
//!   io-uring-register call io_uring_register with invalid arguments; exit 0
//!                     if the kernel returns EINVAL, 3 on ENOSYS
//!   shm               create a SysV shared-memory segment; exit 0 if allowed,
//!                     3 if denied
//!   ipc-namespace [HOLD_MS]
//!                     print `/proc/self/ns/ipc`, then remain alive for up to
//!                     2000 milliseconds; exit 0 on success
//!   posix-shm         create, map, use, and unlink a POSIX shared-memory
//!                     object; exit 0 on success, 3 if unavailable
//!   posix-mq          create a POSIX message queue and verify that it appears
//!                     through `/dev/mqueue`; exit 0 on success, 3 otherwise
//!   private-shm-mount verify `/dev/shm` is a tmpfs no larger than 64 MiB
//!                     mounted nosuid,nodev,noexec; exit 0 if so, 3 otherwise
//!   ptrace-self       call ptrace(PTRACE_TRACEME); exit 0 if allowed, 3 if denied
//!   ptrace-child      attach to and inspect a forked child; exit 0 if allowed,
//!                     3 if denied
//!   process-vm-child  write and read a forked child's memory; exit 0 if
//!                     allowed, 3 if denied
//!   process-vm-host PID ADDRESS EXPECTED
//!                     read EXPECTED from ADDRESS in PID; exit 0 if allowed,
//!                     3 if denied
//!   process-vm-target publish a readable marker and wait for stdin to close;
//!                     used as an explicitly ptrace-opted-in host target
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
    use std::mem::size_of;
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
        "tcp-listen-unbound" => {
            // SAFETY: socket takes scalar arguments.
            let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
            if fd < 0 {
                exit(3);
            }
            // listen(2) implicitly binds an unbound TCP socket to an
            // ephemeral port without an explicit bind(2).
            // SAFETY: fd is the live TCP socket created above.
            let rc = unsafe { libc::listen(fd, 1) };
            // SAFETY: fd is owned above.
            unsafe { libc::close(fd) };
            if rc == 0 { exit(0) } else { exit(3) }
        }
        "udp-bind" => {
            let Some(port) = args.get(2).and_then(|port| port.parse::<u16>().ok()) else {
                exit(2);
            };
            match std::net::UdpSocket::bind(("127.0.0.1", port)) {
                Ok(_) => exit(0),
                Err(_) => exit(3),
            }
        }
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
        "unix-connect" => {
            use std::os::unix::net::UnixStream;

            let Some(path) = args.get(2) else {
                exit(2);
            };
            match UnixStream::connect(path) {
                Ok(_) => exit(0),
                Err(_) => exit(3),
            }
        }
        "unix-recv-fd" => {
            use std::io::Read;
            use std::os::fd::{AsRawFd, FromRawFd};
            use std::os::unix::net::UnixStream;

            let (Some(path), Some(expected)) = (args.get(2), args.get(3)) else {
                exit(2);
            };
            let Ok(stream) = UnixStream::connect(path) else {
                exit(3);
            };
            let mut payload = [0u8; 1];
            let mut iov = libc::iovec {
                iov_base: payload.as_mut_ptr().cast(),
                iov_len: payload.len(),
            };
            // `usize` storage gives cmsghdr its required native alignment.
            let mut control = [0usize; 8];
            // SAFETY: all fields are initialized below before recvmsg reads
            // them; the zeroed pointer fields mean no optional addresses.
            let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
            message.msg_iov = &mut iov;
            message.msg_iovlen = 1;
            message.msg_control = control.as_mut_ptr().cast();
            message.msg_controllen = control.len() * size_of::<usize>();
            // SAFETY: message points to live payload and control buffers and
            // stream is a connected Unix socket.
            if unsafe { libc::recvmsg(stream.as_raw_fd(), &mut message, 0) } != 1 {
                exit(3);
            }
            // SAFETY: recvmsg initialized the ancillary-data region described
            // by message; CMSG_FIRSTHDR validates that region's first header.
            let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
            if header.is_null() {
                exit(3);
            }
            #[expect(
                clippy::multiple_unsafe_ops_per_block,
                reason = "validating one cmsghdr requires reading its three fields and CMSG_LEN"
            )]
            // SAFETY: header is non-null and points within message's live
            // control buffer.
            let valid = unsafe {
                (*header).cmsg_level == libc::SOL_SOCKET
                    && (*header).cmsg_type == libc::SCM_RIGHTS
                    && (*header).cmsg_len >= libc::CMSG_LEN(size_of::<libc::c_int>() as _) as usize
            };
            if !valid {
                exit(3);
            }
            #[expect(
                clippy::multiple_unsafe_ops_per_block,
                reason = "CMSG_DATA locates the pointer consumed by read_unaligned"
            )]
            // SAFETY: the validated SCM_RIGHTS payload contains at least one
            // c_int descriptor. read_unaligned also handles UAPI alignment.
            let fd =
                unsafe { std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<libc::c_int>()) };
            if fd < 0 {
                exit(3);
            }
            // SAFETY: SCM_RIGHTS installed a new descriptor owned by this
            // process; File takes ownership and closes it on drop.
            let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
            let mut content = String::new();
            match file.read_to_string(&mut content) {
                Ok(_) if content == *expected => exit(0),
                _ => exit(3),
            }
        }
        "unix-path-roundtrip" => {
            use std::os::unix::net::{UnixListener, UnixStream};

            let Some(path) = args.get(2) else {
                exit(2);
            };
            let Ok(_listener) = UnixListener::bind(path) else {
                exit(3);
            };
            match UnixStream::connect(path) {
                Ok(_) => exit(0),
                Err(_) => exit(3),
            }
        }
        "unix-abstract-roundtrip" => {
            use std::os::linux::net::SocketAddrExt;
            use std::os::unix::net::{SocketAddr, UnixListener, UnixStream};

            let Some(name) = args.get(2) else {
                exit(2);
            };
            let Ok(addr) = SocketAddr::from_abstract_name(name.as_bytes()) else {
                exit(2);
            };
            let Ok(_listener) = UnixListener::bind_addr(&addr) else {
                exit(3);
            };
            match UnixStream::connect_addr(&addr) {
                Ok(_) => exit(0),
                Err(_) => exit(3),
            }
        }
        "signal-zero" => {
            let Some(pid) = args.get(2).and_then(|pid| pid.parse::<libc::pid_t>().ok()) else {
                exit(2);
            };
            // SAFETY: signal 0 performs only permission and existence checks;
            // it never delivers a signal to the target process.
            if unsafe { libc::kill(pid, 0) } == 0 {
                exit(0);
            }
            exit(3);
        }
        "signal-child-zero" => {
            // SAFETY: fork creates one child with no shared Rust execution;
            // the child exits immediately through async-signal-safe _exit.
            let pid = unsafe { libc::fork() };
            if pid < 0 {
                exit(3);
            }
            if pid == 0 {
                // SAFETY: terminates the forked child without running Rust
                // destructors in the post-fork process.
                unsafe { libc::_exit(0) };
            }
            // An exited child remains an addressable zombie until waitpid, so
            // this permission check is race-free and delivers no signal.
            // SAFETY: pid names the child created above; signal 0 is harmless.
            let allowed = unsafe { libc::kill(pid, 0) } == 0;
            let mut status = 0;
            // SAFETY: pid is our unreaped child and status is writable.
            unsafe { libc::waitpid(pid, &mut status, 0) };
            if allowed {
                exit(0);
            }
            exit(3);
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
        "ipc-namespace" => {
            use std::io::Write;

            let hold_ms = args
                .get(2)
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(0)
                .min(2000);
            match std::fs::read_link("/proc/self/ns/ipc") {
                Ok(link) => {
                    print!("{}", link.display());
                    if std::io::stdout().flush().is_err() {
                        exit(3);
                    }
                    std::thread::sleep(std::time::Duration::from_millis(hold_ms));
                    exit(0);
                }
                Err(_) => exit(3),
            }
        }
        "posix-shm" => {
            let name = c"/guardrail-probe-posix-shm";
            // SAFETY: name is a NUL-terminated POSIX shared-memory name and
            // all remaining arguments are scalars.
            let fd = unsafe {
                libc::shm_open(
                    name.as_ptr(),
                    libc::O_CREAT | libc::O_EXCL | libc::O_RDWR,
                    0o600,
                )
            };
            if fd < 0 {
                exit(3);
            }
            // SAFETY: fd is owned above and the length is scalar.
            if unsafe { libc::ftruncate(fd, 4096) } != 0 {
                // SAFETY: fd is owned above.
                unsafe { libc::close(fd) };
                // SAFETY: name identifies the object created above.
                unsafe { libc::shm_unlink(name.as_ptr()) };
                exit(3);
            }
            // SAFETY: fd is owned above and the mapping arguments describe
            // one page backed by that object.
            let mapping = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    4096,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    fd,
                    0,
                )
            };
            if mapping == libc::MAP_FAILED {
                // SAFETY: fd is owned above.
                unsafe { libc::close(fd) };
                // SAFETY: name identifies the object created above.
                unsafe { libc::shm_unlink(name.as_ptr()) };
                exit(3);
            }
            // SAFETY: mapping is a writable page owned above.
            unsafe { mapping.cast::<u8>().write_volatile(0x5a) };
            // SAFETY: mapping remains a readable page owned above.
            let usable = unsafe { mapping.cast::<u8>().read_volatile() == 0x5a };
            // SAFETY: mapping is owned above and has exactly this length.
            unsafe { libc::munmap(mapping, 4096) };
            // SAFETY: fd is owned above.
            unsafe { libc::close(fd) };
            // SAFETY: name identifies the object created above.
            unsafe { libc::shm_unlink(name.as_ptr()) };
            if usable { exit(0) } else { exit(3) }
        }
        "posix-mq" => {
            let name = c"/guardrail-probe-posix-mq";
            // SAFETY: name is NUL-terminated, the scalar flags request a new
            // queue, and a null attribute pointer selects system defaults.
            let descriptor = unsafe {
                libc::mq_open(
                    name.as_ptr(),
                    libc::O_CREAT | libc::O_EXCL | libc::O_RDWR | libc::O_CLOEXEC,
                    0o600,
                    std::ptr::null::<libc::mq_attr>(),
                )
            };
            if descriptor < 0 {
                exit(3);
            }
            let visible = std::fs::metadata("/dev/mqueue/guardrail-probe-posix-mq").is_ok();
            // SAFETY: descriptor identifies the queue created above.
            unsafe { libc::mq_close(descriptor) };
            // SAFETY: name identifies the queue created above.
            unsafe { libc::mq_unlink(name.as_ptr()) };
            if visible { exit(0) } else { exit(3) }
        }
        "private-shm-mount" => {
            let mut fs = std::mem::MaybeUninit::<libc::statfs>::uninit();
            let mut vfs = std::mem::MaybeUninit::<libc::statvfs>::uninit();
            // SAFETY: path is NUL-terminated and the out-pointer references
            // writable storage for the kernel result structure.
            let statfs_rc = unsafe { libc::statfs(c"/dev/shm".as_ptr(), fs.as_mut_ptr()) };
            // SAFETY: path is NUL-terminated and the out-pointer references
            // writable storage for the kernel result structure.
            let statvfs_rc = unsafe { libc::statvfs(c"/dev/shm".as_ptr(), vfs.as_mut_ptr()) };
            if statfs_rc != 0 || statvfs_rc != 0 {
                exit(3);
            }
            // SAFETY: statfs succeeded and initialized its output.
            let fs = unsafe { fs.assume_init() };
            // SAFETY: statvfs succeeded and initialized its output.
            let vfs = unsafe { vfs.assume_init() };
            const TMPFS_MAGIC: libc::c_long = 0x0102_1994;
            let Ok(block_size) = u128::try_from(fs.f_bsize) else {
                exit(3);
            };
            let capacity = u128::from(fs.f_blocks) * block_size;
            let required_flags = libc::ST_NOSUID | libc::ST_NODEV | libc::ST_NOEXEC;
            if fs.f_type == TMPFS_MAGIC
                && capacity <= 64 * 1024 * 1024
                && vfs.f_flag & required_flags == required_flags
            {
                exit(0);
            }
            exit(3);
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
        "ptrace-child" => {
            let marker: libc::c_long = 0x4755_4152;
            // SAFETY: fork creates one child. The child uses only pause and
            // _exit; the parent owns and reaps the resulting pid.
            let pid = unsafe { libc::fork() };
            if pid < 0 {
                exit(3);
            }
            if pid == 0 {
                // SAFETY: pause has no arguments. The parent terminates this
                // process after completing the inspection.
                unsafe { libc::pause() };
                // SAFETY: do not run Rust destructors in the forked child.
                unsafe { libc::_exit(0) };
            }

            // SAFETY: pid names our live child and the remaining arguments
            // are unused by PTRACE_ATTACH.
            let attached = unsafe {
                libc::ptrace(
                    libc::PTRACE_ATTACH,
                    pid,
                    std::ptr::null_mut::<libc::c_void>(),
                    std::ptr::null_mut::<libc::c_void>(),
                )
            } == 0;
            if !attached {
                kill_and_reap(pid);
                exit(3);
            }
            let mut wait_status = 0;
            // SAFETY: pid is the attached child and wait_status is writable.
            if unsafe { libc::waitpid(pid, &mut wait_status, 0) } < 0 {
                kill_and_reap(pid);
                exit(3);
            }
            // fork preserves virtual addresses, so marker has the same
            // address and value in the child until it is inspected here.
            // SAFETY: pid is stopped under ptrace and marker's address points
            // to a live c_long in the child.
            let value = unsafe {
                libc::ptrace(
                    libc::PTRACE_PEEKDATA,
                    pid,
                    std::ptr::addr_of!(marker).cast_mut().cast::<libc::c_void>(),
                    std::ptr::null_mut::<libc::c_void>(),
                )
            };
            // SAFETY: pid is still stopped under ptrace; signal 0 resumes it
            // without delivering a signal.
            let detached = unsafe {
                libc::ptrace(
                    libc::PTRACE_DETACH,
                    pid,
                    std::ptr::null_mut::<libc::c_void>(),
                    std::ptr::null_mut::<libc::c_void>(),
                )
            } == 0;
            kill_and_reap(pid);
            if detached && value == marker {
                exit(0);
            }
            exit(3);
        }
        "process-vm-child" => {
            let marker: libc::c_long = 0x4755_4152;
            // SAFETY: fork creates one child. The child uses only pause and
            // _exit; the parent owns and reaps the resulting pid.
            let pid = unsafe { libc::fork() };
            if pid < 0 {
                exit(3);
            }
            if pid == 0 {
                // SAFETY: pause has no arguments. The parent terminates this
                // process after completing the inspection.
                unsafe { libc::pause() };
                // SAFETY: do not run Rust destructors in the forked child.
                unsafe { libc::_exit(0) };
            }

            let replacement: libc::c_long = 0x5354_4554;
            let local_write = libc::iovec {
                iov_base: std::ptr::addr_of!(replacement).cast_mut().cast(),
                iov_len: size_of::<libc::c_long>(),
            };
            let remote = libc::iovec {
                iov_base: std::ptr::addr_of!(marker).cast_mut().cast(),
                iov_len: size_of::<libc::c_long>(),
            };
            // SAFETY: both iovecs reference live c_long objects, and pid is
            // our child with the same mapped address for marker.
            let written = unsafe { libc::process_vm_writev(pid, &local_write, 1, &remote, 1, 0) };

            let mut observed: libc::c_long = 0;
            let local_read = libc::iovec {
                iov_base: std::ptr::addr_of_mut!(observed).cast(),
                iov_len: size_of::<libc::c_long>(),
            };
            // SAFETY: both iovecs reference live c_long objects, and pid is
            // our child with the same mapped address for marker.
            let read = unsafe { libc::process_vm_readv(pid, &local_read, 1, &remote, 1, 0) };
            kill_and_reap(pid);

            let wanted =
                isize::try_from(size_of::<libc::c_long>()).expect("c_long size fits isize");
            if written == wanted && read == wanted && observed == replacement {
                exit(0);
            }
            exit(3);
        }
        "process-vm-host" => {
            let Some(pid) = args.get(2).and_then(|pid| pid.parse::<libc::pid_t>().ok()) else {
                exit(2);
            };
            let Some(address) = args
                .get(3)
                .and_then(|address| address.parse::<usize>().ok())
            else {
                exit(2);
            };
            let Some(expected) = args
                .get(4)
                .and_then(|expected| expected.parse::<libc::c_long>().ok())
            else {
                exit(2);
            };
            let mut observed: libc::c_long = 0;
            let local = libc::iovec {
                iov_base: std::ptr::addr_of_mut!(observed).cast(),
                iov_len: size_of::<libc::c_long>(),
            };
            let remote = libc::iovec {
                iov_base: address as *mut libc::c_void,
                iov_len: size_of::<libc::c_long>(),
            };
            // SAFETY: local points to writable storage. The remote address is
            // supplied by the test process; process_vm_readv reports an error
            // instead of dereferencing it in this process when access fails.
            let read = unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) };
            let wanted =
                isize::try_from(size_of::<libc::c_long>()).expect("c_long size fits isize");
            if read == wanted && observed == expected {
                exit(0);
            }
            exit(3);
        }
        "process-vm-target" => {
            use std::io::{Read, Write};

            let marker: libc::c_long = 0x4755_4152;
            // Opt out of Yama's ancestry restriction so an unsandboxed sibling
            // probe establishes that ordinary credentials permit this read.
            // Landlock must still deny a reader in a child domain.
            // SAFETY: PR_SET_PTRACER takes a scalar pid;
            // PR_SET_PTRACER_ANY means any process otherwise permitted by the
            // regular ptrace access checks.
            let rc = unsafe {
                libc::prctl(
                    libc::PR_SET_PTRACER,
                    libc::PR_SET_PTRACER_ANY,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                )
            };
            if rc != 0 {
                let error = std::io::Error::last_os_error();
                // Without Yama, no LSM handles PR_SET_PTRACER: the LSM hook
                // returns -ENOSYS and generic prctl turns the unknown option
                // into EINVAL. That means no exception is needed, so let the
                // unsandboxed baseline below determine ordinary access.
                if error.raw_os_error() != Some(libc::EINVAL) {
                    exit(3);
                }
            }
            println!(
                "{} {} {marker}",
                std::process::id(),
                std::ptr::addr_of!(marker) as usize
            );
            if std::io::stdout().flush().is_err() {
                exit(3);
            }
            let mut byte = [0u8; 1];
            // EOF is the parent test's signal to exit.
            if std::io::stdin().read(&mut byte).is_err() {
                exit(3);
            }
            exit(0);
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
                 socketpair-unix|socketpair-unix-dgram-sendto|tcp-bind|tcp-listen-unbound|\
                 udp-bind|tcp-connect|\
                 unix-bind-listen|unix-connect|unix-path-roundtrip|unix-abstract-roundtrip|\
                 signal-zero|signal-child-zero|\
                 io-uring-setup|io-uring-enter|io-uring-register|shm|\
                 ipc-namespace|posix-shm|posix-mq|private-shm-mount|\
                 ptrace-self|ptrace-child|process-vm-child|process-vm-host|process-vm-target|\
                 unshare-user|mount|mount-setattr|kexec-load|bpf> [arg]"
            );
            exit(2);
        }
    }
}

#[cfg(target_os = "linux")]
fn kill_and_reap(pid: libc::pid_t) {
    // SAFETY: pid is a child created by this process. SIGKILL ensures it
    // cannot remain paused.
    unsafe { libc::kill(pid, libc::SIGKILL) };
    // SAFETY: pid names our child; waitpid reaps it before the probe exits.
    unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
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
