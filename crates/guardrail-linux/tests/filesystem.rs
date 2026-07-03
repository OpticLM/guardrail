#![cfg(target_os = "linux")]

//! Filesystem-confinement intent tests: read, write, and execute grants are
//! separate, no system paths are granted by default, and reads/writes are denied
//! unless explicitly granted. Modeled after `tests/resource_limits.rs`.
//!
//! These exercise observable behavior — does the probe's `read`/`write`
//! succeed (exit 0) or get denied (exit 3) — not the internal sequence of
//! Landlock calls.

use std::os::unix::fs::PermissionsExt;
use std::process::Command;

use guardrail_core::{Error, FsAccess};
use guardrail_linux::LinuxBackend;
use tempfile::TempDir;

mod common;

fn probe(args: &[&str]) -> Command {
    common::probe(args)
}

/// Run the probe under `config`, return whether it exited 0 (allowed).
fn allowed(config: &guardrail_core::SandboxConfig, args: &[&str]) -> bool {
    let mut child = config
        .spawn_with(&LinuxBackend::new(), probe(args))
        .expect("spawn");
    child.wait().expect("wait").success()
}

#[test]
fn target_binary_runs_with_explicit_runtime_grants() {
    let config = common::base().build();
    assert!(
        allowed(&config, &["echo-env", "PATH"]),
        "the sandboxed binary must run when read and execute are explicitly granted"
    );
}

#[test]
fn read_grant_does_not_allow_execute() {
    if !common::landlock_enforced() {
        eprintln!("skipping: Landlock not enforced on this kernel");
        return;
    }

    let exe_dir = common::probe_path().parent().unwrap().to_path_buf();
    let config = common::read_only_base()
        .fs([FsAccess::Read(exe_dir)])
        .build();
    let result = config.spawn_with(&LinuxBackend::new(), probe(&["echo-env", "PATH"]));

    match result {
        Err(Error::Spawn(err)) => assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied),
        Err(other) => panic!("expected spawn permission denial, got {other:?}"),
        Ok(mut child) => {
            let _ = child.kill();
            panic!("read-only filesystem grant must not allow executing the probe");
        }
    }
}

#[test]
fn write_grant_does_not_allow_execute() {
    if !common::landlock_enforced() {
        eprintln!("skipping: Landlock not enforced on this kernel");
        return;
    }

    let tmp = TempDir::new().unwrap();
    let copied_probe = tmp.path().join("copied-probe");
    std::fs::copy(common::probe_path(), &copied_probe).unwrap();

    let mut permissions = std::fs::metadata(&copied_probe).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&copied_probe, permissions).unwrap();

    let config = common::base()
        .fs([FsAccess::Write(tmp.path().into())])
        .build();
    let result = config.spawn_with(&LinuxBackend::new(), Command::new(&copied_probe));

    match result {
        Err(Error::Spawn(err)) => assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied),
        Err(other) => panic!("expected spawn permission denial, got {other:?}"),
        Ok(mut child) => {
            let _ = child.kill();
            panic!("write filesystem grant must not allow executing a file");
        }
    }
}

#[test]
fn execute_grant_does_not_allow_read() {
    if !common::landlock_enforced() {
        eprintln!("skipping: Landlock not enforced on this kernel");
        return;
    }

    let tmp = TempDir::new().unwrap();
    let secret = tmp.path().join("secret.txt");
    std::fs::write(&secret, b"top secret").unwrap();
    let secret_s = secret.to_str().unwrap();

    let config = common::base()
        .fs([FsAccess::Execute(tmp.path().into())])
        .build();
    assert!(
        !allowed(&config, &["read-file", secret_s]),
        "execute grants must not imply read access"
    );
}

#[test]
fn system_paths_are_not_readable_without_explicit_grant() {
    if !common::landlock_enforced() {
        eprintln!("skipping: Landlock not enforced on this kernel");
        return;
    }
    if !std::path::Path::new("/etc/passwd").exists() {
        eprintln!("skipping: /etc/passwd does not exist on this host");
        return;
    }

    let config = common::base().build();
    assert!(
        !allowed(&config, &["read-file", "/etc/passwd"]),
        "the backend must not add builtin read grants for system paths"
    );
}

#[test]
fn read_is_denied_without_grant_and_allowed_with_grant() {
    if !common::landlock_enforced() {
        eprintln!("skipping: Landlock not enforced on this kernel");
        return;
    }

    let tmp = TempDir::new().unwrap();
    let secret = tmp.path().join("secret.txt");
    std::fs::write(&secret, b"top secret").unwrap();
    let secret_s = secret.to_str().unwrap();

    let denied = common::base().build();
    assert!(
        !allowed(&denied, &["read-file", secret_s]),
        "reading an un-granted path must be denied"
    );

    // Allowed: grant read on the temp dir.
    let granted = common::base()
        .fs([FsAccess::Read(tmp.path().into())])
        .build();
    assert!(
        allowed(&granted, &["read-file", secret_s]),
        "reading a granted path must succeed"
    );
}

#[test]
fn write_is_denied_without_grant_and_allowed_with_write_grant() {
    if !common::landlock_enforced() {
        eprintln!("skipping: Landlock not enforced on this kernel");
        return;
    }

    let tmp = TempDir::new().unwrap();
    let target = tmp.path().join("out.txt");
    let target_s = target.to_str().unwrap();

    // Read-only grant on the temp dir → write denied.
    let ro = common::base()
        .fs([FsAccess::Read(tmp.path().into())])
        .build();
    assert!(
        !allowed(&ro, &["write-file", target_s]),
        "writing under a read-only grant must be denied"
    );

    // Write grant → allowed.
    let rw = common::base()
        .fs([FsAccess::Write(tmp.path().into())])
        .build();
    assert!(
        allowed(&rw, &["write-file", target_s]),
        "writing under a write grant must succeed"
    );
}
