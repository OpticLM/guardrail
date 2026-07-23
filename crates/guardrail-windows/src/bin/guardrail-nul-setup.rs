//! Host setup helper for the guardrail null-device write grant.
//!
//! Run once per boot from an elevated context. With no arguments it applies the
//! grant; with `--check` it reports whether the grant is already present
//! (exit 0 = present, exit 3 = absent) without needing elevation.

#![cfg(windows)]

use std::process::exit;

fn main() {
    let check = std::env::args().nth(1).as_deref() == Some("--check");

    if check {
        match guardrail_windows::null_device_write_configured() {
            Ok(true) => {
                println!("null-device write grant: present");
                exit(0);
            }
            Ok(false) => {
                println!("null-device write grant: absent");
                exit(3);
            }
            Err(err) => {
                eprintln!("failed to query the null-device DACL: {err}");
                exit(2);
            }
        }
    }

    match guardrail_windows::configure_null_device_write() {
        Ok(()) => {
            println!("null-device write grant applied");
        }
        Err(err) => {
            eprintln!("failed to configure the null device (run elevated): {err}");
            exit(1);
        }
    }
}
