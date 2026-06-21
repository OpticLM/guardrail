#![cfg(target_os = "linux")]

use std::process::{Command, Stdio};

use guardrail_core::{IpcPolicy, NetworkPolicy, SandboxConfig, ViolationKind};
use guardrail_linux::LinuxBackend;
use guardrail_linux::diagnostics::explain;

mod common;

fn probe(args: &[&str]) -> Command {
    common::probe(args)
}

fn run(config: &SandboxConfig, args: &[&str]) -> std::process::ExitStatus {
    let mut child = config
        .spawn_with(&LinuxBackend::new(), probe(args))
        .expect("spawn");
    child.wait().expect("wait")
}

#[test]
fn success_yields_no_violation() {
    let config = common::base().build();
    let status = run(&config, &["echo-env", "PATH"]);
    assert!(explain(&config, status).is_none());
}

#[test]
fn blocked_network_is_diagnosed_as_seccomp() {
    let config = common::base().network(NetworkPolicy::Deny).build();
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
    let config = common::base().ipc(IpcPolicy::Strict).build();
    let status = run(&config, &["shm"]);
    let v = explain(&config, status).expect("should diagnose a violation");
    assert_eq!(v.kind, ViolationKind::Seccomp);
}

#[test]
fn cpu_limit_is_diagnosed_as_resource_limit() {
    let config = common::base().cpu_time_limit_secs(1).build();
    let status = run(&config, &["spin"]);
    let v = explain(&config, status).expect("should diagnose a violation");
    assert_eq!(v.kind, ViolationKind::ResourceLimit);
}

#[test]
fn violation_display_includes_summary_and_suggestions() {
    let config = common::base().network(NetworkPolicy::Deny).build();
    let status = run(&config, &["socket-inet"]);
    let v = explain(&config, status).unwrap();
    let rendered = v.to_string();
    assert!(rendered.contains("SIGSYS"));
    assert!(
        rendered.contains("  - "),
        "Display should bullet the suggestions"
    );
}
