//! Host setup helper for the guardrail sandbox grants.
//!
//! Modes (all but `--check` need elevation):
//!
//! * *(no arguments)* — apply every grant.
//! * `--check` — report each grant's presence (exit 0 = all present, 3 = any
//!   absent) without elevation.
//! * `--register` — apply every grant now and register a SYSTEM scheduled
//!   task that re-runs this binary at every boot. The device grants (null
//!   device, mount-point manager) live on kernel objects whose security
//!   descriptors reset at boot; the traverse grants are persistent NTFS ACEs
//!   and simply no-op on re-application.
//! * `--unregister` — delete the scheduled task (grants stay until reboot /
//!   `--revert`).
//! * `--revert` — subtract every grant this helper adds, restoring the
//!   pre-existing ACEs bit-for-bit. Workspace-ancestor traverse grants
//!   stamped during policy application are per-namespace state and are not
//!   touched here.

#![cfg(windows)]

use std::io;
use std::process::{Command, exit};

const TASK_NAME: &str = "guardrail-host-setup";

const GRANTS: [(
    &str,
    fn() -> io::Result<bool>,
    fn() -> io::Result<()>,
    fn() -> io::Result<()>,
); 3] = [
    (
        "null-device write grant",
        guardrail_windows::null_device_write_configured,
        guardrail_windows::configure_null_device_write,
        guardrail_windows::revert_null_device_write,
    ),
    (
        "mount-point-manager access grant",
        guardrail_windows::mount_point_manager_access_configured,
        guardrail_windows::configure_mount_point_manager_access,
        guardrail_windows::revert_mount_point_manager_access,
    ),
    (
        "system ancestor traverse grants",
        guardrail_windows::system_traverse_grants_configured,
        guardrail_windows::configure_system_traverse_grants,
        guardrail_windows::revert_system_traverse_grants,
    ),
];

fn main() {
    match std::env::args().nth(1).as_deref() {
        None => apply(),
        Some("--check") => check(),
        Some("--register") => {
            apply();
            register();
        }
        Some("--unregister") => unregister(),
        Some("--revert") => revert(),
        Some(other) => {
            eprintln!(
                "unknown option {other}; usage: guardrail-host-setup [--check|--register|--unregister|--revert]"
            );
            exit(2);
        }
    }
}

fn apply() {
    for (label, _, configure, _) in GRANTS {
        match configure() {
            Ok(()) => println!("{label} applied"),
            Err(err) => {
                eprintln!("failed to apply the {label} (run elevated): {err}");
                exit(1);
            }
        }
    }
}

fn check() {
    let mut all_present = true;
    for (label, configured, _, _) in GRANTS {
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

fn revert() {
    for (label, _, _, revert) in GRANTS {
        match revert() {
            Ok(()) => println!("{label} reverted"),
            Err(err) => {
                eprintln!("failed to revert the {label} (run elevated): {err}");
                exit(1);
            }
        }
    }
}

fn register() {
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(err) => {
            eprintln!("failed to resolve the helper's own path: {err}");
            exit(1);
        }
    };
    // ONSTART + SYSTEM: runs elevated at every boot, before any user session,
    // so the per-boot device grants are back before sandboxes spawn.
    let status = Command::new("schtasks")
        .args([
            "/Create",
            "/F",
            "/TN",
            TASK_NAME,
            "/SC",
            "ONSTART",
            "/RU",
            "SYSTEM",
            "/TR",
        ])
        .arg(format!("\"{}\"", exe.display()))
        .status();
    match status {
        Ok(status) if status.success() => {
            println!("scheduled boot task {TASK_NAME} registered");
        }
        Ok(status) => {
            eprintln!("schtasks /Create exited with {status} (run elevated)");
            exit(1);
        }
        Err(err) => {
            eprintln!("failed to run schtasks: {err}");
            exit(1);
        }
    }
}

fn unregister() {
    let status = Command::new("schtasks")
        .args(["/Delete", "/F", "/TN", TASK_NAME])
        .status();
    match status {
        Ok(status) if status.success() => {
            println!("scheduled boot task {TASK_NAME} removed");
        }
        Ok(status) => {
            eprintln!("schtasks /Delete exited with {status} (run elevated)");
            exit(1);
        }
        Err(err) => {
            eprintln!("failed to run schtasks: {err}");
            exit(1);
        }
    }
}
