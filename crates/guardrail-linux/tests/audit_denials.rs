//! Opted-in sandboxes (`linux_audit_denials`) install their Landlock domains
//! and seccomp filters with the kernel's logging flags. Logging must not
//! change enforcement, and the flags must be accepted by this kernel.

#![cfg(target_os = "linux")]

use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;

use guardrail_core::{Backend, FsAccess, NetworkPolicy, SandboxConfig};
use guardrail_linux::LinuxBackend;
use tempfile::TempDir;

mod common;

fn audited() -> SandboxConfig {
    let mut config = common::base();
    config.linux_audit_denials = true;
    config
}

fn status(config: &SandboxConfig, args: &[&str]) -> ExitStatus {
    let mut child = LinuxBackend::new(config.clone())
        .expect("backend")
        .spawn(common::probe(args))
        .expect("spawn");
    child.wait().expect("wait")
}

#[test]
fn logged_landlock_layers_still_spawn() {
    // OutboundOnly adds the network layer, so all three Landlock domains are
    // created with the logging flag on this kernel's ABI.
    let mut config = audited();
    config.network = NetworkPolicy::OutboundOnly;
    assert_eq!(status(&config, &["echo-env", "X"]).code(), Some(0));
}

#[test]
fn logged_landlock_still_denies_writes() {
    let tmp = TempDir::new().expect("tempdir");
    let target = tmp.path().join("out.txt");
    let mut config = audited();
    config.fs.push(FsAccess::ReadAllow(tmp.path().into()));
    assert_eq!(
        status(&config, &["write-file", target.to_str().expect("utf-8")]).code(),
        Some(3),
        "a write under a read-only grant must stay denied"
    );
}

#[test]
fn logged_socket_filter_still_denies_inet() {
    assert_eq!(status(&audited(), &["socket-inet"]).code(), Some(3));
}

#[test]
fn logged_eperm_filter_still_denies_bpf() {
    assert_eq!(status(&audited(), &["bpf"]).code(), Some(3));
}

#[test]
fn logged_trap_filter_still_kills_mount() {
    assert_eq!(status(&audited(), &["mount"]).signal(), Some(libc::SIGSYS));
}

#[test]
fn unlogged_enosys_filter_still_lets_fork_fall_back() {
    assert_eq!(status(&audited(), &["fork"]).code(), Some(0));
}
