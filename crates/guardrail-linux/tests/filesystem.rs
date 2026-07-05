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
    let mut cmd = probe(args);
    cmd.env_clear();
    cmd.envs(&config.env);
    let mut child = LinuxBackend::new().spawn(config, cmd).expect("spawn");
    child.wait().expect("wait").success()
}

#[test]
fn target_binary_runs_with_explicit_runtime_grants() {
    let config = common::base();
    assert!(
        allowed(&config, &["echo-env", "PATH"]),
        "the sandboxed binary must run when read and execute are explicitly granted"
    );
}

#[test]
fn read_rule_does_not_grant_execute() {
    if !common::landlock_enforced() {
        eprintln!("skipping: Landlock not enforced on this kernel");
        return;
    }

    let exe_dir = common::probe_path().parent().unwrap().to_path_buf();
    let mut config = common::read_only_base();
    config.fs.extend([FsAccess::ReadAllow(exe_dir)]);
    let mut cmd = probe(&["echo-env", "PATH"]);
    cmd.env_clear();
    cmd.envs(&config.env);
    let result = LinuxBackend::new().spawn(&config, cmd);

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
fn write_rule_does_not_grant_execute() {
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

    let mut config = common::base();
    config.fs.extend([FsAccess::WriteAllow(tmp.path().into())]);
    let mut cmd = Command::new(&copied_probe);
    cmd.env_clear();
    cmd.envs(&config.env);
    let result = LinuxBackend::new().spawn(&config, cmd);

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
fn execute_rule_does_not_grant_read() {
    if !common::landlock_enforced() {
        eprintln!("skipping: Landlock not enforced on this kernel");
        return;
    }

    let tmp = TempDir::new().unwrap();
    let secret = tmp.path().join("secret.txt");
    std::fs::write(&secret, b"top secret").unwrap();
    let secret_s = secret.to_str().unwrap();

    let mut config = common::base();
    config.fs.extend([FsAccess::ExecuteAllow(tmp.path().into())]);
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

    let config = common::base();
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

    let denied = common::base();
    assert!(
        !allowed(&denied, &["read-file", secret_s]),
        "reading an un-granted path must be denied"
    );

    // Allowed: grant read on the temp dir.
    let mut granted = common::base();
    granted.fs.extend([FsAccess::ReadAllow(tmp.path().into())]);
    assert!(
        allowed(&granted, &["read-file", secret_s]),
        "reading a granted path must succeed"
    );
}

#[test]
fn read_allow_then_read_deny_denies_child_but_allows_sibling() {
    if !common::landlock_enforced() {
        eprintln!("skipping: Landlock not enforced on this kernel");
        return;
    }

    let tmp = TempDir::new().unwrap();
    let public = tmp.path().join("public.txt");
    let secret = tmp.path().join("secret.txt");
    std::fs::write(&public, b"public").unwrap();
    std::fs::write(&secret, b"secret").unwrap();

    let mut config = common::base();
    config.fs.extend([
        FsAccess::ReadAllow(tmp.path().into()),
        FsAccess::ReadDeny(secret.clone()),
    ]);

    assert!(allowed(&config, &["read-file", public.to_str().unwrap()]));
    assert!(!allowed(&config, &["read-file", secret.to_str().unwrap()]));
}

#[test]
fn read_deny_then_read_allow_reopens_child_only() {
    if !common::landlock_enforced() {
        eprintln!("skipping: Landlock not enforced on this kernel");
        return;
    }

    let tmp = TempDir::new().unwrap();
    let public = tmp.path().join("public.txt");
    let other = tmp.path().join("other.txt");
    std::fs::write(&public, b"public").unwrap();
    std::fs::write(&other, b"other").unwrap();

    let mut config = common::base();
    config.fs.extend([
        FsAccess::ReadDeny(tmp.path().into()),
        FsAccess::ReadAllow(public.clone()),
    ]);

    assert!(allowed(&config, &["read-file", public.to_str().unwrap()]));
    assert!(!allowed(&config, &["read-file", other.to_str().unwrap()]));
}

#[test]
fn later_read_allow_overrides_same_path_deny() {
    if !common::landlock_enforced() {
        eprintln!("skipping: Landlock not enforced on this kernel");
        return;
    }

    let tmp = TempDir::new().unwrap();
    let public = tmp.path().join("public.txt");
    std::fs::write(&public, b"public").unwrap();

    let mut config = common::base();
    config.fs.extend([
        FsAccess::ReadAllow(tmp.path().into()),
        FsAccess::ReadDeny(tmp.path().into()),
        FsAccess::ReadAllow(tmp.path().into()),
    ]);

    assert!(allowed(&config, &["read-file", public.to_str().unwrap()]));
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
    let mut ro = common::base();
    ro.fs.extend([FsAccess::ReadAllow(tmp.path().into())]);
    assert!(
        !allowed(&ro, &["write-file", target_s]),
        "writing under a read-only grant must be denied"
    );

    // Write grant → allowed.
    let mut rw = common::base();
    rw.fs.extend([FsAccess::WriteAllow(tmp.path().into())]);
    assert!(
        allowed(&rw, &["write-file", target_s]),
        "writing under a write grant must succeed"
    );
}

#[test]
fn write_rule_does_not_grant_read() {
    if !common::landlock_enforced() {
        eprintln!("skipping: Landlock not enforced on this kernel");
        return;
    }

    let tmp = TempDir::new().unwrap();
    let target = tmp.path().join("out.txt");
    let secret = tmp.path().join("secret.txt");
    std::fs::write(&secret, b"secret").unwrap();

    let mut config = common::base();
    config.fs.extend([FsAccess::WriteAllow(tmp.path().into())]);

    assert!(allowed(&config, &["write-file", target.to_str().unwrap()]));
    assert!(!allowed(&config, &["read-file", secret.to_str().unwrap()]));
}

#[test]
fn missing_deny_descendant_inside_allow_fails_before_spawn() {
    let tmp = TempDir::new().unwrap();
    let missing = tmp.path().join("future-secret");

    let mut config = common::base();
    config.fs.extend([
        FsAccess::ReadAllow(tmp.path().into()),
        FsAccess::ReadDeny(missing),
    ]);

    let mut cmd = probe(&["echo-env", "PATH"]);
    cmd.env_clear();
    cmd.envs(&config.env);
    let result = LinuxBackend::new().spawn(&config, cmd);

    assert!(matches!(
        result,
        Err(Error::Confinement {
            stage: "landlock",
            ..
        })
    ));
}
