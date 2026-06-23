use std::process::Command;

use guardrail_core::{IpcPolicy, SandboxConfig};
use guardrail_linux::LinuxBackend;

mod common;

fn probe(args: &[&str]) -> Command {
    common::probe(args)
}

fn allowed(config: &SandboxConfig, args: &[&str]) -> bool {
    let mut child = config
        .spawn_with(&LinuxBackend::new(), probe(args))
        .expect("spawn");
    child.wait().expect("wait").success()
}

#[test]
fn strict_blocks_shared_memory() {
    let config = common::base().ipc(IpcPolicy::Strict).build();
    assert!(
        !allowed(&config, &["shm"]),
        "SysV shared memory must be blocked under Strict IPC"
    );
}

#[test]
fn relaxed_allows_shared_memory() {
    let config = common::base().ipc(IpcPolicy::Relaxed).build();
    assert!(
        allowed(&config, &["shm"]),
        "shared memory must be allowed under Relaxed IPC"
    );
}

#[test]
fn ptrace_is_blocked_at_both_levels() {
    for level in [IpcPolicy::Strict, IpcPolicy::Relaxed] {
        let config = common::base().ipc(level).build();
        assert!(
            !allowed(&config, &["ptrace-self"]),
            "ptrace must be blocked under {level:?} IPC"
        );
    }
}

#[test]
fn default_ipc_is_strict() {
    // The builder default must be Strict (matches guardrail-core's default).
    let config = common::base().build();
    assert!(
        !allowed(&config, &["shm"]),
        "default IPC level must behave as Strict (shm blocked)"
    );
}
