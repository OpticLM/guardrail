//! Test helper exercised by guardrail-macos integration tests.
//!
//! Usage: `guardrail-macos-probe <COMMAND> [ARG]`

#[cfg(target_os = "macos")]
use std::process::exit;

#[cfg(target_os = "macos")]
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("");

    match cmd {
        "noop" => exit(0),
        "echo-env" => {
            let name = args.get(2).map(String::as_str).unwrap_or("");
            print!("{}", std::env::var(name).unwrap_or_default());
            exit(0);
        }
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
                eprintln!("read-fd failed: {}", std::io::Error::last_os_error());
                exit(3);
            }
            if &buf[..n as usize] == expected.as_bytes() {
                exit(0);
            }
            eprintln!("read-fd content mismatch");
            exit(3);
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
        "apply-profile" => {
            let path = args.get(2).map(String::as_str).unwrap_or("");
            let profile = std::fs::read_to_string(path).unwrap_or_else(|err| {
                eprintln!("read profile failed: {err}");
                exit(2);
            });
            let profile = std::ffi::CString::new(profile).unwrap_or_else(|_| {
                eprintln!("profile contains an interior NUL byte");
                exit(2);
            });
            let mut error_buffer = std::ptr::null_mut();
            // SAFETY: profile is nul-terminated and error_buffer is a valid
            // out-pointer. This probe is single-threaded and has not forked.
            let rc = unsafe { sandbox_init(profile.as_ptr(), 0, &mut error_buffer) };
            if rc == 0 {
                if !error_buffer.is_null() {
                    // SAFETY: sandbox_init returned this diagnostic buffer.
                    unsafe { sandbox_free_error(error_buffer) };
                }
                exit(0);
            }
            if !error_buffer.is_null() {
                // SAFETY: a failing sandbox_init returns a nul-terminated
                // diagnostic string owned by sandbox_free_error.
                let message = unsafe { std::ffi::CStr::from_ptr(error_buffer) };
                eprintln!("{}", message.to_string_lossy());
                // SAFETY: error_buffer came from sandbox_init above.
                unsafe { sandbox_free_error(error_buffer) };
            }
            exit(3);
        }
        _ => {
            eprintln!(
                "usage: guardrail-macos-probe <noop|echo-env|read-file|read-fd|socket-inet|tcp-connect|apply-profile> [arg]"
            );
            exit(2);
        }
    }
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn sandbox_init(
        profile: *const libc::c_char,
        flags: u64,
        error_buffer: *mut *mut libc::c_char,
    ) -> libc::c_int;
    fn sandbox_free_error(error_buffer: *mut libc::c_char);
}

#[cfg(not(target_os = "macos"))]
fn main() {}
