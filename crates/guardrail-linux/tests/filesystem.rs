//! Filesystem-confinement intent tests: the sandboxed binary still runs
//! under the default ruleset, reads are denied unless granted, and writes
//! are denied unless write-granted. Modeled after `tests/resource_limits.rs`.
//!
//! These exercise observable behavior — does the probe's `read`/`write`
//! succeed (exit 0) or get denied (exit 3) — not the internal sequence of
//! Landlock calls.

use std::process::{Command, Stdio};

use guardrail_core::SandboxBuilder;
use guardrail_linux::LinuxBackend;
use tempfile::TempDir;

fn probe(args: &[&str]) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_guardrail-probe"));
    c.args(args).stdout(Stdio::null()).stderr(Stdio::null());
    c
}

/// Run the probe under `config`, return whether it exited 0 (allowed).
fn allowed(config: &guardrail_core::SandboxConfig, args: &[&str]) -> bool {
    let mut child = config
        .spawn_with(&LinuxBackend::new(), probe(args))
        .expect("spawn");
    child.wait().expect("wait").success()
}

/// Returns true if Landlock appears to be enforcing on this kernel. Used to skip
/// deny-assertions on unsupported kernels (CI). On this project's dev host
/// (kernel 7.0.8) it returns true.
fn landlock_enforced() -> bool {
    std::fs::read_to_string("/sys/kernel/security/lsm")
        .map(|s| s.split(',').any(|m| m.trim() == "landlock"))
        .unwrap_or(false)
}

#[test]
fn target_binary_runs_under_default_confinement() {
    // The probe itself lives under the target dir; the default system read dirs
    // plus the binary's own path must let it execute. Grant read on the
    // binary's directory to be safe across `target/` locations.
    let exe = std::path::PathBuf::from(env!("CARGO_BIN_EXE_guardrail-probe"));
    let dir = exe.parent().unwrap().to_path_buf();
    let config = SandboxBuilder::new().allow_read(dir).build();
    assert!(
        allowed(&config, &["echo-env", "PATH"]),
        "the sandboxed binary must be loadable/executable under default rules"
    );
}

#[test]
fn read_is_denied_without_grant_and_allowed_with_grant() {
    if !landlock_enforced() {
        eprintln!("skipping: Landlock not enforced on this kernel");
        return;
    }
    let exe = std::path::PathBuf::from(env!("CARGO_BIN_EXE_guardrail-probe"));
    let exe_dir = exe.parent().unwrap().to_path_buf();

    let tmp = TempDir::new().unwrap();
    let secret = tmp.path().join("secret.txt");
    std::fs::write(&secret, b"top secret").unwrap();
    let secret_s = secret.to_str().unwrap();

    // Denied: only the binary dir is readable, not the temp dir.
    let denied = SandboxBuilder::new().allow_read(&exe_dir).build();
    assert!(
        !allowed(&denied, &["read-file", secret_s]),
        "reading an un-granted path must be denied"
    );

    // Allowed: grant read on the temp dir.
    let granted = SandboxBuilder::new()
        .allow_read(&exe_dir)
        .allow_read(tmp.path())
        .build();
    assert!(
        allowed(&granted, &["read-file", secret_s]),
        "reading a granted path must succeed"
    );
}

#[test]
fn write_is_denied_without_grant_and_allowed_with_write_grant() {
    if !landlock_enforced() {
        eprintln!("skipping: Landlock not enforced on this kernel");
        return;
    }
    let exe = std::path::PathBuf::from(env!("CARGO_BIN_EXE_guardrail-probe"));
    let exe_dir = exe.parent().unwrap().to_path_buf();

    let tmp = TempDir::new().unwrap();
    let target = tmp.path().join("out.txt");
    let target_s = target.to_str().unwrap();

    // Read-only grant on the temp dir → write denied.
    let ro = SandboxBuilder::new()
        .allow_read(&exe_dir)
        .allow_read(tmp.path())
        .build();
    assert!(
        !allowed(&ro, &["write-file", target_s]),
        "writing under a read-only grant must be denied"
    );

    // Write grant → allowed.
    let rw = SandboxBuilder::new()
        .allow_read(&exe_dir)
        .allow_write(tmp.path())
        .build();
    assert!(
        allowed(&rw, &["write-file", target_s]),
        "writing under a write grant must succeed"
    );
}
