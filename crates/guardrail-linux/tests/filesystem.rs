#![cfg(target_os = "linux")]

//! Filesystem-confinement intent tests: read, write, and execute grants are
//! separate, no system paths are granted by default, and reads/writes are denied
//! unless explicitly granted. Modeled after `tests/resource_limits.rs`.
//!
//! These exercise observable behavior — does the probe's `read`/`write`
//! succeed (exit 0) or get denied (exit 3) — not the internal sequence of
//! Landlock calls.

use std::os::unix::fs::PermissionsExt;

use guardrail_core::{Backend, Error, FsAccess, SandboxCommand};
use guardrail_linux::LinuxBackend;
use tempfile::TempDir;

mod common;

fn probe(args: &[&str]) -> SandboxCommand {
    common::probe(args)
}

/// Run the probe under `config`, return whether it exited 0 (allowed).
fn allowed(config: &guardrail_core::SandboxConfig, args: &[&str]) -> bool {
    let cmd = probe(args);
    let mut child = LinuxBackend::new(config.clone())
        .expect("backend")
        .spawn(cmd)
        .expect("spawn");
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
    let cmd = probe(&["echo-env", "PATH"]);
    let result = LinuxBackend::new(config.clone())
        .expect("backend")
        .spawn(cmd);

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
    let cmd = SandboxCommand::new(&copied_probe);
    let result = LinuxBackend::new(config.clone())
        .expect("backend")
        .spawn(cmd);

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
    config
        .fs
        .extend([FsAccess::ExecuteAllow(tmp.path().into())]);
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
    if let Some(reason) = common::mount_masking_unsupported_reason() {
        eprintln!("skipping: {reason}");
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

    let result = LinuxBackend::new(config);

    assert!(matches!(
        result,
        Err(Error::Confinement {
            stage: "landlock",
            ..
        })
    ));
}

/// Run `args` under an already-constructed backend, returning whether the
/// probe exited 0. Unlike [`allowed`], this reuses the backend so tests can
/// change the filesystem between construction and spawn.
fn spawn_allowed(backend: &LinuxBackend, args: &[&str]) -> bool {
    let cmd = probe(args);
    let mut child = backend.spawn(cmd).expect("spawn");
    child.wait().expect("wait").success()
}

/// Issue #19: the ordered policy must stay live after backend construction —
/// a sibling created later matches the parent allow, and a descendant created
/// later under the denied subtree matches the deny.
#[test]
fn files_created_after_backend_construction_follow_the_ordered_policy() {
    if !common::landlock_enforced() {
        eprintln!("skipping: Landlock not enforced on this kernel");
        return;
    }
    if let Some(reason) = common::mount_masking_unsupported_reason() {
        eprintln!("skipping: {reason}");
        return;
    }

    let tmp = TempDir::new().unwrap();
    let secret = tmp.path().join("secret");
    std::fs::create_dir(&secret).unwrap();
    std::fs::write(secret.join("key.txt"), b"key").unwrap();

    let mut config = common::base();
    config.fs.extend([
        FsAccess::ReadAllow(tmp.path().into()),
        FsAccess::ReadDeny(secret.clone()),
    ]);
    let backend = LinuxBackend::new(config.clone()).expect("backend");

    // Created only after the backend (and its compiled policy) exist.
    let future = tmp.path().join("future.txt");
    std::fs::write(&future, b"future").unwrap();
    let late_secret = secret.join("late.txt");
    std::fs::write(&late_secret, b"late").unwrap();

    assert!(
        spawn_allowed(&backend, &["read-file", future.to_str().unwrap()]),
        "a sibling created after construction matches the parent allow"
    );
    assert!(
        !spawn_allowed(
            &backend,
            &["read-file", secret.join("key.txt").to_str().unwrap()]
        ),
        "the pre-existing denied descendant stays denied"
    );
    assert!(
        !spawn_allowed(&backend, &["read-file", late_secret.to_str().unwrap()]),
        "a descendant created after construction under the denied subtree stays denied"
    );
}

/// Issue #19: the policy must stay live even for files created while a
/// sandboxed child is already running.
#[test]
fn file_created_while_child_is_running_is_readable() {
    if !common::landlock_enforced() {
        eprintln!("skipping: Landlock not enforced on this kernel");
        return;
    }
    if let Some(reason) = common::mount_masking_unsupported_reason() {
        eprintln!("skipping: {reason}");
        return;
    }

    let tmp = TempDir::new().unwrap();
    let secret = tmp.path().join("secret");
    std::fs::create_dir(&secret).unwrap();

    let mut config = common::base();
    config.fs.extend([
        FsAccess::ReadAllow(tmp.path().into()),
        FsAccess::ReadDeny(secret),
    ]);
    let backend = LinuxBackend::new(config.clone()).expect("backend");

    let appearing = tmp.path().join("appears.txt");
    let cmd = probe(&["wait-read-file", appearing.to_str().unwrap(), "10"]);
    let mut child = backend.spawn(cmd).expect("spawn");

    std::thread::sleep(std::time::Duration::from_millis(200));
    std::fs::write(&appearing, b"now you see me").unwrap();

    assert!(
        child.wait().expect("wait").success(),
        "a file created while the child runs matches the parent allow"
    );
}

/// A grandchild re-allowed beneath a denied parent keeps working, including
/// for files created after backend construction, while new siblings inside
/// the denied parent stay hidden.
#[test]
fn reallowed_grandchild_stays_live_under_denied_parent() {
    if !common::landlock_enforced() {
        eprintln!("skipping: Landlock not enforced on this kernel");
        return;
    }
    if let Some(reason) = common::mount_masking_unsupported_reason() {
        eprintln!("skipping: {reason}");
        return;
    }

    let tmp = TempDir::new().unwrap();
    let child = tmp.path().join("child");
    let grand = child.join("grand");
    std::fs::create_dir_all(&grand).unwrap();

    let mut config = common::base();
    config.fs.extend([
        FsAccess::ReadAllow(tmp.path().into()),
        FsAccess::ReadDeny(child.clone()),
        FsAccess::ReadAllow(grand.clone()),
    ]);
    let backend = LinuxBackend::new(config.clone()).expect("backend");

    let new_grand = grand.join("new.txt");
    std::fs::write(&new_grand, b"grand").unwrap();
    let new_hidden = child.join("other.txt");
    std::fs::write(&new_hidden, b"hidden").unwrap();
    let new_sibling = tmp.path().join("sibling.txt");
    std::fs::write(&new_sibling, b"sibling").unwrap();

    assert!(
        spawn_allowed(&backend, &["read-file", new_grand.to_str().unwrap()]),
        "a file created after construction in the re-allowed grandchild is readable"
    );
    assert!(
        !spawn_allowed(&backend, &["read-file", new_hidden.to_str().unwrap()]),
        "a file created after construction in the denied parent stays hidden"
    );
    assert!(
        spawn_allowed(&backend, &["read-file", new_sibling.to_str().unwrap()]),
        "a sibling outside the denied parent is readable"
    );
}

/// A write deny beneath a write allow is a read-only mask, not a hide: reads
/// keep working (including for files created later), writes are denied.
#[test]
fn write_deny_under_write_allow_is_readonly_but_readable() {
    if !common::landlock_enforced() {
        eprintln!("skipping: Landlock not enforced on this kernel");
        return;
    }
    if let Some(reason) = common::mount_masking_unsupported_reason() {
        eprintln!("skipping: {reason}");
        return;
    }

    let tmp = TempDir::new().unwrap();
    let locked = tmp.path().join("locked");
    std::fs::create_dir(&locked).unwrap();
    std::fs::write(locked.join("data.txt"), b"data").unwrap();

    let mut config = common::base();
    config.fs.extend([
        FsAccess::ReadAllow(tmp.path().into()),
        FsAccess::WriteAllow(tmp.path().into()),
        FsAccess::WriteDeny(locked.clone()),
    ]);
    let backend = LinuxBackend::new(config.clone()).expect("backend");

    let late = locked.join("late.txt");
    std::fs::write(&late, b"late").unwrap();

    assert!(
        spawn_allowed(
            &backend,
            &["write-file", tmp.path().join("new.txt").to_str().unwrap()]
        ),
        "writes under the allow keep working"
    );
    assert!(
        !spawn_allowed(
            &backend,
            &["write-file", locked.join("x.txt").to_str().unwrap()]
        ),
        "creating files under the write deny is denied"
    );
    assert!(
        !spawn_allowed(&backend, &["write-file", late.to_str().unwrap()]),
        "writing a file created after construction under the write deny is denied"
    );
    assert!(
        spawn_allowed(
            &backend,
            &["read-file", locked.join("data.txt").to_str().unwrap()]
        ),
        "reads under a write-only deny keep working"
    );
    assert!(
        spawn_allowed(&backend, &["read-file", late.to_str().unwrap()]),
        "reads of files created after construction under a write-only deny keep working"
    );
}

/// Denying read while write stays allowed beneath the same path has no
/// faithful mount encoding; the backend must refuse it precisely.
#[test]
fn read_deny_with_covered_write_allow_is_unsupported() {
    if !common::landlock_enforced() {
        eprintln!("skipping: Landlock not enforced on this kernel");
        return;
    }

    let tmp = TempDir::new().unwrap();
    let secret = tmp.path().join("secret");
    std::fs::create_dir(&secret).unwrap();

    let mut config = common::base();
    config.fs.extend([
        FsAccess::ReadAllow(tmp.path().into()),
        FsAccess::WriteAllow(tmp.path().into()),
        FsAccess::ReadDeny(secret),
    ]);

    assert!(matches!(
        LinuxBackend::new(config),
        Err(Error::Unsupported(_))
    ));
}
