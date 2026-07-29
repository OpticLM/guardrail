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
        "cwd-report" => {
            // Bisect what "could not determine current directory" failures
            // actually hit: raw cwd query, canonicalization (opens the dir
            // handle), and listing.
            match env::current_dir() {
                Ok(dir) => eprintln!("current_dir ok: {}", dir.display()),
                Err(err) => {
                    eprintln!("current_dir failed: {err}");
                    exit(3);
                }
            }
            match fs::canonicalize(".") {
                Ok(dir) => eprintln!("canonicalize ok: {}", dir.display()),
                Err(err) => eprintln!("canonicalize failed: {err}"),
            }
            match fs::read_dir(".") {
                Ok(entries) => eprintln!("read_dir ok: {} entries", entries.count()),
                Err(err) => eprintln!("read_dir failed: {err}"),
            }
            #[cfg(windows)]
            final_path_report();
            #[cfg(windows)]
            mountmgr_report();
        }
        "open-bits" => {
            // Open `path` with an explicit desired-access mask (hex) and report
            // success/failure — for bisecting which access bit a tool's open
            // is denied on.
            let path = required_arg(&args, 2);
            let mask = u32::from_str_radix(required_arg(&args, 3).trim_start_matches("0x"), 16)
                .unwrap_or_else(|_| exit(2));
            #[cfg(windows)]
            {
                use std::os::windows::ffi::OsStrExt;
                #[link(name = "kernel32")]
                unsafe extern "system" {
                    fn CreateFileW(
                        lpfilename: *const u16,
                        dwdesiredaccess: u32,
                        dwsharemode: u32,
                        lpsecurityattributes: *const core::ffi::c_void,
                        dwcreationdisposition: u32,
                        dwflagsandattributes: u32,
                        htemplatefile: *mut core::ffi::c_void,
                    ) -> *mut core::ffi::c_void;
                    fn CloseHandle(hobject: *mut core::ffi::c_void) -> i32;
                }
                let wide: Vec<u16> = std::ffi::OsStr::new(path)
                    .encode_wide()
                    .chain(std::iter::once(0))
                    .collect();
                let handle = unsafe {
                    CreateFileW(
                        wide.as_ptr(),
                        mask,
                        0x7,
                        std::ptr::null(),
                        3, // OPEN_EXISTING
                        0,
                        std::ptr::null_mut(),
                    )
                };
                if handle as isize == -1 {
                    eprintln!(
                        "open-bits {mask:#010x} failed: {}",
                        std::io::Error::last_os_error()
                    );
                    exit(3);
                }
                eprintln!("open-bits {mask:#010x} ok");
                unsafe { CloseHandle(handle) };
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

#[cfg(windows)]
fn final_path_report() {
    // Open the cwd directory handle with zero access + backup semantics
    // (exactly what std's canonicalize does), then try
    // GetFinalPathNameByHandleW with each volume-name flavor to pin down
    // which step access-denies under the sandbox.
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle};

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateFileW(
            lpfilename: *const u16,
            dwdesiredaccess: u32,
            dwsharemode: u32,
            lpsecurityattributes: *const core::ffi::c_void,
            dwcreationdisposition: u32,
            dwflagsandattributes: u32,
            htemplatefile: *mut core::ffi::c_void,
        ) -> *mut core::ffi::c_void;
        fn GetFinalPathNameByHandleW(
            hfile: *mut core::ffi::c_void,
            lpszfilepath: *mut u16,
            cchfilepath: u32,
            dwflags: u32,
        ) -> u32;
    }

    const FILE_SHARE_ALL: u32 = 0x1 | 0x2 | 0x4;
    const OPEN_EXISTING: u32 = 3;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const VOLUME_NAME_DOS: u32 = 0x0;
    const VOLUME_NAME_GUID: u32 = 0x1;
    const VOLUME_NAME_NT: u32 = 0x2;

    let path: Vec<u16> = std::ffi::OsStr::new(".")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            0,
            FILE_SHARE_ALL,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut(),
        )
    };
    if handle as isize == -1 {
        eprintln!(
            "open-cwd-0-access failed: {}",
            std::io::Error::last_os_error()
        );
        return;
    }
    eprintln!("open-cwd-0-access ok");
    let file = std::mem::ManuallyDrop::new(unsafe {
        std::os::windows::io::OwnedHandle::from_raw_handle(handle)
    });
    for (label, flag) in [
        ("VOLUME_NAME_DOS", VOLUME_NAME_DOS),
        ("VOLUME_NAME_GUID", VOLUME_NAME_GUID),
        ("VOLUME_NAME_NT", VOLUME_NAME_NT),
    ] {
        let mut buffer = [0u16; 1024];
        let len = unsafe {
            GetFinalPathNameByHandleW(file.as_raw_handle(), buffer.as_mut_ptr(), 1024, flag)
        };
        if len == 0 {
            eprintln!(
                "final-path {label} failed: {}",
                std::io::Error::last_os_error()
            );
        } else {
            let text = String::from_utf16_lossy(&buffer[..len.min(1024) as usize]);
            eprintln!("final-path {label} ok: {text}");
        }
    }
}

#[cfg(windows)]
fn mountmgr_report() {
    // Distinguish "cannot open \\.\MountPointManager" (DACL gate) from "open
    // succeeds but the IOCTL is refused" (driver-level sandbox check).
    use std::os::windows::ffi::OsStrExt;

    #[repr(C)]
    struct UnicodeString {
        length: u16,
        maximum_length: u16,
        buffer: *mut u16,
    }
    #[repr(C)]
    struct ObjectAttributes {
        length: u32,
        root_directory: *mut core::ffi::c_void,
        object_name: *mut UnicodeString,
        attributes: u32,
        security_descriptor: *mut core::ffi::c_void,
        security_quality_of_service: *mut core::ffi::c_void,
    }
    #[repr(C)]
    struct IoStatusBlock {
        status: isize,
        information: usize,
    }

    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtOpenFile(
            filehandle: *mut *mut core::ffi::c_void,
            desiredaccess: u32,
            objectattributes: *mut ObjectAttributes,
            iostatusblock: *mut IoStatusBlock,
            shareaccess: u32,
            openoptions: u32,
        ) -> i32;
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn DeviceIoControl(
            hdevice: *mut core::ffi::c_void,
            dwiocontrolcode: u32,
            lpinbuffer: *const core::ffi::c_void,
            ninbuffersize: u32,
            lpoutbuffer: *mut core::ffi::c_void,
            noutbuffersize: u32,
            lpbytesreturned: *mut u32,
            lpoverlapped: *mut core::ffi::c_void,
        ) -> i32;
        fn CloseHandle(hobject: *mut core::ffi::c_void) -> i32;
    }

    const FILE_SHARE_ALL: u32 = 0x7;
    const FILE_EXECUTE: u32 = 0x20;
    const SYNCHRONIZE: u32 = 0x0010_0000;
    const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x20;
    /// CTL_CODE(MOUNTMGRCONTROLTYPE, 12, METHOD_BUFFERED, FILE_ANY_ACCESS)
    const IOCTL_MOUNTMGR_QUERY_DOS_VOLUME_PATH: u32 = 0x006D_0030;

    let mut name: Vec<u16> = std::ffi::OsStr::new(r"\??\MountPointManager")
        .encode_wide()
        .collect();
    let mut unicode = UnicodeString {
        length: (name.len() * 2) as u16,
        maximum_length: (name.len() * 2) as u16,
        buffer: name.as_mut_ptr(),
    };
    let mut handle: *mut core::ffi::c_void = std::ptr::null_mut();
    for (label, access, options) in [
        ("FILE_EXECUTE", FILE_EXECUTE, 0u32),
        (
            "FILE_EXECUTE|SYNCHRONIZE",
            FILE_EXECUTE | SYNCHRONIZE,
            FILE_SYNCHRONOUS_IO_NONALERT,
        ),
    ] {
        let mut attributes = ObjectAttributes {
            length: std::mem::size_of::<ObjectAttributes>() as u32,
            root_directory: std::ptr::null_mut(),
            object_name: &mut unicode,
            attributes: 0x40, // OBJ_CASE_INSENSITIVE
            security_descriptor: std::ptr::null_mut(),
            security_quality_of_service: std::ptr::null_mut(),
        };
        let mut status_block = IoStatusBlock {
            status: 0,
            information: 0,
        };
        let mut opened: *mut core::ffi::c_void = std::ptr::null_mut();
        let status = unsafe {
            NtOpenFile(
                &mut opened,
                access,
                &mut attributes,
                &mut status_block,
                FILE_SHARE_ALL,
                options,
            )
        };
        if status < 0 {
            eprintln!("mountmgr NtOpenFile {label} failed: NTSTATUS {status:#010x}");
        } else {
            eprintln!("mountmgr NtOpenFile {label} ok");
            if handle.is_null() {
                handle = opened;
            } else {
                unsafe { CloseHandle(opened) };
            }
        }
    }
    if handle.is_null() {
        return;
    }

    // Query the DOS path of the volume backing the current directory's NT
    // device name — the same IOCTL GetFinalPathNameByHandleW(VOLUME_NAME_DOS)
    // issues.
    let device: Vec<u16> = std::ffi::OsStr::new(r"\Device\HarddiskVolume3")
        .encode_wide()
        .collect();
    // MOUNTMGR_TARGET_NAME: USHORT DeviceNameLength; WCHAR DeviceName[].
    let name_bytes = device.len() * 2;
    let mut input = vec![0u8; 2 + name_bytes];
    input[..2].copy_from_slice(&(name_bytes as u16).to_le_bytes());
    for (index, unit) in device.iter().enumerate() {
        input[2 + index * 2..4 + index * 2].copy_from_slice(&unit.to_le_bytes());
    }
    let mut output = [0u8; 1024];
    let mut returned = 0u32;
    let ok = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_MOUNTMGR_QUERY_DOS_VOLUME_PATH,
            input.as_ptr().cast(),
            input.len() as u32,
            output.as_mut_ptr().cast(),
            output.len() as u32,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        eprintln!(
            "mountmgr QUERY_DOS_VOLUME_PATH failed: {}",
            std::io::Error::last_os_error()
        );
    } else {
        let multi_sz_len = u32::from_le_bytes(output[..4].try_into().unwrap()) as usize;
        let units: Vec<u16> = output[4..4 + multi_sz_len.min(1000)]
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes(pair.try_into().unwrap()))
            .collect();
        eprintln!(
            "mountmgr QUERY_DOS_VOLUME_PATH ok: {}",
            String::from_utf16_lossy(&units)
        );
    }
    unsafe { CloseHandle(handle) };
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
