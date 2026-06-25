//! Test helper exercised by guardrail-macos integration tests.
//!
//! Usage: `guardrail-macos-probe <COMMAND> [ARG]`

use std::process::exit;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("");

    match cmd {
        "noop" => exit(0),
        "read-file" => {
            let path = args.get(2).map(String::as_str).unwrap_or("");
            match std::fs::read(path) {
                Ok(_) => exit(0),
                Err(err) => {
                    eprintln!("read-file failed: {err}");
                    exit(3);
                }
            }
        }
        "socket-inet" => {
            // SAFETY: socket() takes scalar args; close the fd if created.
            let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
            if fd < 0 {
                eprintln!("socket-inet failed: {}", std::io::Error::last_os_error());
                exit(3);
            }
            // SAFETY: fd was returned by socket() above and is owned here.
            unsafe { libc::close(fd) };
            exit(0);
        }
        "tcp-connect" => {
            let addr = args.get(2).map(String::as_str).unwrap_or("");
            match std::net::TcpStream::connect(addr) {
                Ok(_) => exit(0),
                Err(err) => {
                    eprintln!("tcp-connect failed: {err}");
                    exit(3);
                }
            }
        }
        #[cfg(target_os = "macos")]
        "apply-profile" => {
            let path = args.get(2).map(String::as_str).unwrap_or("");
            let profile = std::fs::read_to_string(path).unwrap_or_else(|err| {
                eprintln!("read profile failed: {err}");
                exit(2);
            });
            match painless_belt::ffi::sandbox_init(&profile, 0) {
                Ok(()) => exit(0),
                Err(err) => {
                    eprintln!("{err}");
                    exit(3);
                }
            }
        }
        _ => {
            eprintln!(
                "usage: guardrail-macos-probe <noop|read-file|socket-inet|tcp-connect|apply-profile> [arg]"
            );
            exit(2);
        }
    }
}
