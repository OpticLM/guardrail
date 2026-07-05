#![cfg(target_os = "linux")]

use std::process::Command;

use guardrail_core::{Backend, IpcPolicy, SandboxConfig};
use guardrail_linux::LinuxBackend;

mod common;

fn probe(args: &[&str]) -> Command {
    common::probe(args)
}

fn allowed(config: &SandboxConfig, args: &[&str]) -> bool {
    let mut cmd = probe(args);
    cmd.env_clear();
    cmd.envs(&config.env);
    let mut child = LinuxBackend::new(config.clone())
        .expect("backend")
        .spawn(cmd)
        .expect("spawn");
    child.wait().expect("wait").success()
}

#[test]
fn strict_blocks_shared_memory() {
    let mut config = common::base();
    config.ipc = IpcPolicy::Strict;
    assert!(
        !allowed(&config, &["shm"]),
        "SysV shared memory must be blocked under Strict IPC"
    );
}

#[test]
fn relaxed_allows_shared_memory() {
    let mut config = common::base();
    config.ipc = IpcPolicy::Relaxed;
    assert!(
        allowed(&config, &["shm"]),
        "shared memory must be allowed under Relaxed IPC"
    );
}

#[test]
fn ptrace_is_blocked_at_both_levels() {
    for level in [IpcPolicy::Strict, IpcPolicy::Relaxed] {
        let mut config = common::base();
        config.ipc = level;
        assert!(
            !allowed(&config, &["ptrace-self"]),
            "ptrace must be blocked under {level:?} IPC"
        );
    }
}

#[test]
fn default_ipc_is_strict() {
    // The default must be Strict (matches guardrail-core's default).
    let config = common::base();
    assert!(
        !allowed(&config, &["shm"]),
        "default IPC level must behave as Strict (shm blocked)"
    );
}
