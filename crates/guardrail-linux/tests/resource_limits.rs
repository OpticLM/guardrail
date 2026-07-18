#![cfg(target_os = "linux")]

//! Verifies that resource limits actually constrain the child (intent-level):
//! with a small memory cap a large allocation fails; with a CPU
//! cap a busy loop is killed within a bounded time.

use std::time::{Duration, Instant};

use guardrail_core::Backend;
use guardrail_linux::LinuxBackend;

mod common;

#[test]
fn memory_limit_blocks_large_allocation() {
    // 64 MiB address-space cap; ask the child to grab 512 MiB.
    let mut config = common::base();
    config.limits.memory_bytes = Some(64 * 1024 * 1024);
    let mut cmd = common::probe(&[]);
    cmd.arg("alloc").arg("512");
    cmd.env_clear();
    cmd.envs(&config.env);
    let mut child = LinuxBackend::new(config.clone())
        .expect("backend")
        .spawn(cmd)
        .expect("spawn");
    let status = child.wait().expect("wait");
    assert!(
        !status.success(),
        "allocation of 512 MiB must fail under a 64 MiB RLIMIT_AS"
    );
}

#[test]
fn without_limit_the_same_allocation_succeeds() {
    // Control: no cap → the 512 MiB allocation succeeds. Guards against the
    // probe being broken in a way that makes the test above pass spuriously.
    let config = common::base();
    let mut cmd = common::probe(&[]);
    cmd.arg("alloc").arg("512");
    cmd.env_clear();
    cmd.envs(&config.env);
    let mut child = LinuxBackend::new(config.clone())
        .expect("backend")
        .spawn(cmd)
        .expect("spawn");
    let status = child.wait().expect("wait");
    assert!(
        status.success(),
        "512 MiB should allocate when unconstrained"
    );
}

#[test]
fn cpu_time_limit_kills_busy_loop() {
    // 1s CPU cap on an infinite spin. RLIMIT_CPU soft→SIGXCPU, hard→SIGKILL.
    let mut config = common::base();
    config.limits.cpu_time_secs = Some(1);
    let mut cmd = common::probe(&[]);
    cmd.arg("spin");
    cmd.env_clear();
    cmd.envs(&config.env);
    let mut child = LinuxBackend::new(config.clone())
        .expect("backend")
        .spawn(cmd)
        .expect("spawn");

    let start = Instant::now();
    let status = child.wait().expect("wait");
    let elapsed = start.elapsed();

    assert!(
        !status.success(),
        "spinner must be killed, not exit cleanly"
    );
    assert!(
        elapsed < Duration::from_secs(10),
        "spinner should die from the CPU limit well under 10s (took {elapsed:?})"
    );
}

#[test]
fn process_limit_blocks_fork() {
    // RLIMIT_NPROC counts every process of the real UID, so a cap of 1 is
    // already exceeded by the probe itself and fork(2) must fail with EAGAIN.
    // The limit is not enforced for privileged users, so skip under root.
    // SAFETY: geteuid takes no arguments and cannot fail.
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("skipping: RLIMIT_NPROC is not enforced for privileged users");
        return;
    }
    let mut config = common::base();
    config.limits.max_processes = Some(1);
    let mut cmd = common::probe(&["fork"]);
    cmd.env_clear();
    cmd.envs(&config.env);
    let mut child = LinuxBackend::new(config)
        .expect("backend")
        .spawn(cmd)
        .expect("spawn");
    let status = child.wait().expect("wait");
    assert_eq!(
        status.code(),
        Some(3),
        "fork must be denied under RLIMIT_NPROC = 1"
    );
}

#[test]
fn without_limit_the_same_fork_succeeds() {
    // Control: guards against the fork probe being broken in a way that makes
    // the denial test above pass spuriously.
    let config = common::base();
    let mut cmd = common::probe(&["fork"]);
    cmd.env_clear();
    cmd.envs(&config.env);
    let mut child = LinuxBackend::new(config)
        .expect("backend")
        .spawn(cmd)
        .expect("spawn");
    let status = child.wait().expect("wait");
    assert!(status.success(), "fork should succeed when unconstrained");
}
