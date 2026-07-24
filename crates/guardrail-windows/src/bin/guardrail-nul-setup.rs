//! Host setup helper for the guardrail device grants (null device +
//! mount-point manager).
//!
//! Run once per boot from an elevated context. With no arguments it applies
//! both grants; with `--check` it reports whether they are already present
//! (exit 0 = all present, exit 3 = any absent) without needing elevation.

#![cfg(windows)]

use std::io;
use std::process::exit;

const GRANTS: [(&str, fn() -> io::Result<bool>, fn() -> io::Result<()>); 2] = [
    (
        "null-device write grant",
        guardrail_windows::null_device_write_configured,
        guardrail_windows::configure_null_device_write,
    ),
    (
        "mount-point-manager access grant",
        guardrail_windows::mount_point_manager_access_configured,
        guardrail_windows::configure_mount_point_manager_access,
    ),
];

fn main() {
    let check = std::env::args().nth(1).as_deref() == Some("--check");

    if check {
        let mut all_present = true;
        for (label, configured, _) in GRANTS {
            match configured() {
                Ok(true) => println!("{label}: present"),
                Ok(false) => {
                    println!("{label}: absent");
                    all_present = false;
                }
                Err(err) => {
                    eprintln!("failed to query the DACL for the {label}: {err}");
                    exit(2);
                }
            }
        }
        exit(if all_present { 0 } else { 3 });
    }

    for (label, _, configure) in GRANTS {
        match configure() {
            Ok(()) => println!("{label} applied"),
            Err(err) => {
                eprintln!("failed to apply the {label} (run elevated): {err}");
                exit(1);
            }
        }
    }
}
