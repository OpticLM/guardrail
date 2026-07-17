#![cfg(target_os = "macos")]

//! Inherited-descriptor hygiene: a descriptor the parent holds open without
//! `FD_CLOEXEC` must not survive into the sandboxed child. Seatbelt cannot
//! revoke access to already-open descriptors, so inheriting one would bypass
//! the filesystem and network policy entirely.

use std::os::fd::AsRawFd;
use std::process::{Command, Stdio};

use guardrail_core::Backend;
use guardrail_macos::MacosBackend;

mod common;

const SECRET: &str = "inherited-fd-secret";

/// A secret file removed on drop, opened with `FD_CLOEXEC` cleared to emulate
/// a parent that holds a leakable descriptor (std opens files close-on-exec,
/// so the flag must be cleared explicitly).
struct LeakedSecret {
    path: std::path::PathBuf,
    file: std::fs::File,
}

impl LeakedSecret {
    fn create(label: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("guardrail-macos-fd-{label}-{}", std::process::id()));
        std::fs::write(&path, SECRET).unwrap();
        let file = std::fs::File::open(&path).unwrap();
        // SAFETY: fcntl with F_SETFD takes scalar args only, on an owned fd.
        let rc = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, 0) };
        assert_eq!(rc, 0, "clearing FD_CLOEXEC failed");
        Self { path, file }
    }

    fn fd_arg(&self) -> String {
        self.file.as_raw_fd().to_string()
    }
}

impl Drop for LeakedSecret {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Control: without the sandbox the leaked descriptor is readable in the
/// child. Proves the harness actually leaks, so the denial test below cannot
/// pass vacuously.
#[test]
fn unsandboxed_child_reads_the_leaked_fd() {
    let secret = LeakedSecret::create("control");

    let status = Command::new(common::probe_path())
        .args(["read-fd", &secret.fd_arg(), SECRET])
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
    let secret = LeakedSecret::create("sandboxed");

    let config = common::base();
    let mut cmd = common::probe(&["read-fd", &secret.fd_arg(), SECRET]);
    cmd.env_clear();
    cmd.envs(&config.env);
    let mut child = MacosBackend::new(config)
        .expect("backend")
        .spawn(cmd)
        .expect("spawn");

    assert_eq!(
        child.wait().expect("wait").code(),
        Some(3),
        "a non-CLOEXEC parent descriptor must not reach the sandboxed child"
    );
}
