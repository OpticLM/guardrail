//! Test helper exercised by guardrail-linux integration tests.
//!
//! Usage: `guardrail-probe <COMMAND> [ARG]`
//!
//! Exit codes:
//!   0   operation succeeded / allowed
//!   3   operation failed because it was denied (the expected sandboxed result)
//!   2   usage error / unknown command
//!
//! Commands:
//!   echo-env <NAME>   print the value of env var NAME (empty if unset), exit 0
//!   alloc <MB>        try to allocate and touch <MB> megabytes; exit 0 if it
//!                     succeeds, exit 3 if allocation fails
//!   spin              busy-loop forever (for CPU-time-limit tests)
//!   read-file <PATH>  read PATH; exit 0 if allowed, exit 3 if denied/failed
//!   write-file <PATH> write one byte to PATH; exit 0 if allowed, 3 if denied
//!   socket-inet       create an AF_INET TCP socket; exit 0 if allowed, 3 if denied
//!   tcp-bind          bind a TCP listener on 127.0.0.1:0; exit 0 if allowed,
//!                     3 if denied
//!   shm               create a SysV shared-memory segment; exit 0 if allowed,
//!                     3 if denied
//!   ptrace-self       call ptrace(PTRACE_TRACEME); exit 0 if allowed, 3 if denied

use std::process::exit;

fn main() {
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
        "socket-inet" => {
            // SAFETY: socket() takes scalar args; close the fd if created.
            let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
            if fd < 0 {
                exit(3);
            }
            // SAFETY: fd was returned by socket() above and is owned here.
            unsafe { libc::close(fd) };
            exit(0);
        }
        "tcp-bind" => match std::net::TcpListener::bind(("127.0.0.1", 0)) {
            Ok(_) => exit(0),
            Err(_) => exit(3),
        },
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
                 <echo-env|alloc|spin|read-file|write-file|socket-inet|tcp-bind|shm|ptrace-self> [arg]"
            );
            exit(2);
        }
    }
}
