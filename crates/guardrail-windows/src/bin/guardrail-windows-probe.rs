//! Deterministic probe commands for Windows backend integration tests.

use std::env;
use std::fs;
use std::hint::black_box;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::process::exit;
use std::time::Duration;

fn main() {
    let args = env::args().collect::<Vec<_>>();
    let command = args.get(1).map(String::as_str).unwrap_or("");

    match command {
        "echo-env" => {
            let name = required_arg(&args, 2);
            print!("{}", env::var(name).unwrap_or_default());
        }
        "check-env" => {
            let name = required_arg(&args, 2);
            let expected = required_arg(&args, 3);
            if env::var(name).as_deref() == Ok(expected) {
                exit(0);
            }
            exit(3);
        }
        "echo-stdio" => {
            // Distinct markers per stream so redirection tests can tell the
            // two apart.
            if std::io::stdout().write_all(b"stdout-marker\n").is_err() {
                exit(3);
            }
            if std::io::stderr().write_all(b"stderr-marker\n").is_err() {
                exit(3);
            }
        }
        "stdin-echo" => {
            let mut buffer = Vec::new();
            if std::io::stdin().read_to_end(&mut buffer).is_err() {
                exit(3);
            }
            if std::io::stdout().write_all(&buffer).is_err() {
                exit(3);
            }
        }
        #[cfg(windows)]
        "read-handle" => {
            use std::os::windows::io::{FromRawHandle, RawHandle};

            let raw = required_arg(&args, 2)
                .parse::<usize>()
                .unwrap_or_else(|_| exit(2));
            // SAFETY: the raw value names a handle only if the parent let it
            // be inherited; ManuallyDrop ensures an arbitrary value is never
            // closed, and the process exits right after the read attempt.
            let mut file =
                std::mem::ManuallyDrop::new(unsafe { fs::File::from_raw_handle(raw as RawHandle) });
            // The test target is a non-empty file, so one readable byte
            // proves the handle actually reached this process.
            let mut buffer = [0u8; 1];
            match file.read_exact(&mut buffer) {
                Ok(()) => exit(0),
                Err(_) => exit(3),
            }
        }
        "alloc" => {
            let mb = required_arg(&args, 2)
                .parse::<usize>()
                .unwrap_or_else(|_| exit(2));
            if allocate_and_touch(mb).is_err() {
                exit(3);
            }
        }
        "spin" => loop {
            std::hint::spin_loop();
        },
        "read-file" => {
            let path = required_arg(&args, 2);
            if fs::read(path).is_err() {
                exit(3);
            }
        }
        "delayed-read-file" => {
            let delay_ms = required_arg(&args, 2)
                .parse::<u64>()
                .unwrap_or_else(|_| exit(2));
            let path = required_arg(&args, 3);
            std::thread::sleep(Duration::from_millis(delay_ms));
            if fs::read(path).is_err() {
                exit(3);
            }
        }
        "write-file" => {
            let path = required_arg(&args, 2);
            if let Err(err) = fs::write(path, b"guardrail") {
                eprintln!("write-file failed: {err}");
                exit(3);
            }
        }
        "write-nul" => {
            // Open the null device for writing, exactly as `> nul` and tools
            // like git and go do. Fails under the restricted token unless the
            // host has granted Authenticated Users write on \Device\Null.
            match fs::OpenOptions::new().write(true).open("\\\\.\\NUL") {
                Ok(mut file) => {
                    if let Err(err) = file.write_all(b"guardrail") {
                        eprintln!("write-nul write failed: {err}");
                        exit(3);
                    }
                }
                Err(err) => {
                    eprintln!("write-nul open failed: {err}");
                    exit(3);
                }
            }
        }
        "read-nul" => match fs::OpenOptions::new().read(true).open("\\\\.\\NUL") {
            Ok(_) => {}
            Err(err) => {
                eprintln!("read-nul open failed: {err}");
                exit(3);
            }
        },
        "overwrite-file" => {
            let path = required_arg(&args, 2);
            let result = fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(path)
                .and_then(|mut file| file.write_all(b"guardrail"));
            if let Err(err) = result {
                eprintln!("overwrite-file failed: {err}");
                exit(3);
            }
        }
        "delete-file" => {
            let path = required_arg(&args, 2);
            if let Err(err) = fs::remove_file(path) {
                eprintln!("delete-file failed: {err}");
                exit(3);
            }
        }
        "rename-file" => {
            let from = required_arg(&args, 2);
            let to = required_arg(&args, 3);
            if let Err(err) = fs::rename(from, to) {
                eprintln!("rename-file failed: {err}");
                exit(3);
            }
        }
        "tcp-connect" => {
            let host = required_arg(&args, 2);
            let port = required_arg(&args, 3);
            if tcp_connect(host, port).is_err() {
                exit(3);
            }
        }
        "tcp-bind" => {
            let host = args.get(2).map(String::as_str).unwrap_or("127.0.0.1");
            if TcpListener::bind((host, 0)).is_err() {
                exit(3);
            }
        }
        _ => {
            eprintln!(
                "usage: guardrail-windows-probe <echo-env|check-env|echo-stdio|stdin-echo|read-handle|alloc|spin|read-file|delayed-read-file|write-file|write-nul|overwrite-file|delete-file|rename-file|tcp-connect|tcp-bind [host]> ..."
            );
            exit(2);
        }
    }
}

fn required_arg(args: &[String], index: usize) -> &str {
    args.get(index)
        .map(String::as_str)
        .unwrap_or_else(|| exit(2))
}

fn allocate_and_touch(mb: usize) -> Result<(), ()> {
    let bytes = mb.checked_mul(1024 * 1024).ok_or(())?;
    let mut buffer = Vec::new();
    buffer.try_reserve_exact(bytes).map_err(|_error| ())?;
    buffer.resize(bytes, 0u8);

    for offset in (0..buffer.len()).step_by(4096) {
        if let Some(byte) = buffer.get_mut(offset) {
            *byte = byte.wrapping_add(1);
        }
    }
    black_box(&buffer);
    Ok(())
}

fn tcp_connect(host: &str, port: &str) -> std::io::Result<()> {
    let address = format!("{host}:{port}");
    let mut addresses = address.to_socket_addrs()?;
    let Some(address) = addresses.next() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "no socket address resolved",
        ));
    };
    TcpStream::connect_timeout(&address, Duration::from_secs(2)).map(|_| ())
}
