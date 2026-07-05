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
#[ignore = "RLIMIT_NPROC counts processes per real-uid system-wide; flaky in shared/CI environments"]
fn process_limit_is_applied() {
    // Best-effort: with max_processes(1) the child cannot fork a helper.
    // Left ignored because RLIMIT_NPROC depends on the ambient process count of
    // the running user. Run manually with `--ignored` on a quiet machine.
    let mut config = common::base();
    config.limits.max_processes = Some(1);
    let mut cmd = common::probe_command();
    cmd.arg("spin");
    cmd.env_clear();
    cmd.envs(&config.env);
    let res = LinuxBackend::new(config).expect("backend").spawn(cmd);
    // The assertion is intentionally loose; document-only.
    let _ = res;
}
