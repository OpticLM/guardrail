#![cfg(target_os = "linux")]

//! Inherited-descriptor hygiene: a descriptor the parent holds open without
//! `FD_CLOEXEC` must not survive into the sandboxed child. Landlock and
//! seccomp cannot revoke access to already-open descriptors, so inheriting
//! one would bypass the filesystem and network policy entirely.

use std::os::fd::AsRawFd;
use std::process::{Command, Stdio};

use guardrail_core::Backend;
use guardrail_linux::LinuxBackend;
use tempfile::TempDir;

mod common;

const SECRET: &str = "inherited-fd-secret";

/// Open `secret.txt` under `dir` and clear `FD_CLOEXEC`, emulating a parent
/// that holds a leakable descriptor (std opens files close-on-exec, so the
/// flag must be cleared explicitly).
fn open_secret_without_cloexec(dir: &TempDir) -> std::fs::File {
    let path = dir.path().join("secret.txt");
    std::fs::write(&path, SECRET).expect("write secret");
    let file = std::fs::File::open(&path).expect("open secret");
    // SAFETY: fcntl with F_SETFD takes scalar args only, on an owned fd.
    let rc = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, 0) };
    assert_eq!(rc, 0, "clearing FD_CLOEXEC failed");
    file
}

/// Control: without the sandbox the leaked descriptor is readable in the
/// child. Proves the harness actually leaks, so the denial test below cannot
/// pass vacuously.
#[test]
fn unsandboxed_child_reads_the_leaked_fd() {
    let dir = TempDir::new().unwrap();
    let file = open_secret_without_cloexec(&dir);

    let status = Command::new(common::probe_path())
        .args(["read-fd", &file.as_raw_fd().to_string(), SECRET])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("spawn unsandboxed probe");

    assert_eq!(
        status.code(),
        Some(0),
        "control: an unsandboxed child must be able to read the leaked fd"
    );
}

#[test]
fn sandboxed_child_cannot_use_the_leaked_fd() {
    if !common::landlock_enforced() {
        eprintln!("skipping: Landlock not enforced on this kernel");
        return;
    }

    let dir = TempDir::new().unwrap();
    let file = open_secret_without_cloexec(&dir);

    let config = common::base();
    let cmd = common::probe(&["read-fd", &file.as_raw_fd().to_string(), SECRET]);
    let mut child = LinuxBackend::new(config)
        .expect("backend")
        .spawn(cmd)
        .expect("spawn");

    assert_eq!(
        child.wait().expect("wait").code(),
        Some(3),
        "a non-CLOEXEC parent descriptor must not reach the sandboxed child"
    );
}
