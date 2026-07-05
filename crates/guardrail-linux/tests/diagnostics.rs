#![cfg(target_os = "linux")]

use std::process::Command;

use guardrail_core::{
    Backend, ExplainCtx, IpcPolicy, NetworkPolicy, SandboxConfig, Violation, ViolationKind,
};
use guardrail_linux::LinuxBackend;

mod common;

fn explain(config: &SandboxConfig, status: std::process::ExitStatus) -> Option<Violation> {
    LinuxBackend::new().explain(&ExplainCtx::new(config, status))
}

fn probe(args: &[&str]) -> Command {
    common::probe(args)
}

fn run(config: &SandboxConfig, args: &[&str]) -> std::process::ExitStatus {
    let mut cmd = probe(args);
    cmd.env_clear();
    cmd.envs(&config.env);
    let mut child = LinuxBackend::new().spawn(config, cmd).expect("spawn");
    child.wait().expect("wait")
}

#[test]
fn success_yields_no_violation() {
    let config = common::base();
    let status = run(&config, &["echo-env", "PATH"]);
    assert!(explain(&config, status).is_none());
}

#[test]
fn blocked_network_is_diagnosed_as_seccomp() {
    let mut config = common::base();
    config.network = NetworkPolicy::Deny;
    let status = run(&config, &["socket-inet"]);
    let v = explain(&config, status).expect("should diagnose a violation");
    assert_eq!(v.kind, ViolationKind::Seccomp);
    assert!(
        !v.suggestions.is_empty(),
        "a seccomp violation must suggest a network/IPC policy to relax"
    );
}

#[test]
fn blocked_ipc_is_diagnosed_as_seccomp() {
    let mut config = common::base();
    config.ipc = IpcPolicy::Strict;
    let status = run(&config, &["shm"]);
    let v = explain(&config, status).expect("should diagnose a violation");
    assert_eq!(v.kind, ViolationKind::Seccomp);
}

#[test]
fn cpu_limit_is_diagnosed_as_resource_limit() {
    let mut config = common::base();
    config.limits.cpu_time_secs = Some(1);
    let status = run(&config, &["spin"]);
    let v = explain(&config, status).expect("should diagnose a violation");
    assert_eq!(v.kind, ViolationKind::ResourceLimit);
}

#[test]
fn violation_display_includes_summary_and_suggestions() {
    let mut config = common::base();
    config.network = NetworkPolicy::Deny;
    let status = run(&config, &["socket-inet"]);
    let v = explain(&config, status).unwrap();
    let rendered = v.to_string();
    assert!(rendered.contains("SIGSYS"));
    assert!(
        rendered.contains("  - "),
        "Display should bullet the suggestions"
    );
}
