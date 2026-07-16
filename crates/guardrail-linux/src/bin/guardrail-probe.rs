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
//!   read-file <PATH>  read PATH; exit 0 if allowed, exit 3 if denied/failed
//!   write-file <PATH> write one byte to PATH; exit 0 if allowed, 3 if denied
//!   socket-inet       create an AF_INET TCP socket; exit 0 if allowed, 3 if denied
//!   socket-netlink    create an AF_NETLINK route socket; exit 0 if allowed, 3 if denied
//!   socket-packet     create an AF_PACKET raw socket; exit 0 if allowed, 3 if denied
//!   socket-vsock      create an AF_VSOCK stream socket; exit 0 if allowed, 3 if denied
//!   socket-unix       create an AF_UNIX stream socket; exit 0 if allowed, 3 if denied
//!   tcp-bind          bind a TCP listener on 127.0.0.1:0; exit 0 if allowed,
//!                     3 if denied
//!   io-uring-setup    create an io_uring instance; exit 0 if allowed, 3 on ENOSYS
//!   io-uring-enter    call io_uring_enter with an invalid fd; exit 0 if the
//!                     kernel returns EBADF, 3 on ENOSYS
//!   io-uring-register call io_uring_register with invalid arguments; exit 0
//!                     if the kernel returns EINVAL, 3 on ENOSYS
//!   shm               create a SysV shared-memory segment; exit 0 if allowed,
//!                     3 if denied
//!   ptrace-self       call ptrace(PTRACE_TRACEME); exit 0 if allowed, 3 if denied

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
        "read-file" => {
            let path = args.get(2).map(String::as_str).unwrap_or("");
            match std::fs::read(path) {
                Ok(_) => exit(0),
                Err(_) => exit(3),
            }
        }
        "write-file" => {
            let path = args.get(2).map(String::as_str).unwrap_or("");
            match std::fs::write(path, b"x") {
                Ok(_) => exit(0),
                Err(_) => exit(3),
            }
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
        "tcp-bind" => match std::net::TcpListener::bind(("127.0.0.1", 0)) {
            Ok(_) => exit(0),
            Err(_) => exit(3),
        },
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
        _ => {
            eprintln!(
                "usage: guardrail-probe \
                 <echo-env|alloc|spin|read-file|write-file|socket-inet|socket-netlink|\
                 socket-packet|socket-vsock|socket-unix|tcp-bind|io-uring-setup|io-uring-enter|\
                 io-uring-register|shm|ptrace-self> [arg]"
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
