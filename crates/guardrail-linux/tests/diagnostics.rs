use std::process::{Command, Stdio};

use guardrail_core::{IpcPolicy, NetworkPolicy, SandboxBuilder, SandboxConfig, ViolationKind};
use guardrail_linux::LinuxBackend;
use guardrail_linux::diagnostics::explain;

fn probe(args: &[&str]) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_guardrail-probe"));
    c.args(args).stdout(Stdio::null()).stderr(Stdio::null());
    c
}

fn base() -> SandboxBuilder {
    let exe = std::path::PathBuf::from(env!("CARGO_BIN_EXE_guardrail-probe"));
    SandboxBuilder::new().allow_read(exe.parent().unwrap().to_path_buf())
}

fn run(config: &SandboxConfig, args: &[&str]) -> std::process::ExitStatus {
    let mut child = config
        .spawn_with(&LinuxBackend::new(), probe(args))
        .expect("spawn");
    child.wait().expect("wait")
}

#[test]
fn success_yields_no_violation() {
    let config = base().build();
    let status = run(&config, &["echo-env", "PATH"]);
    assert!(explain(&config, status).is_none());
}

#[test]
fn blocked_network_is_diagnosed_as_seccomp() {
    let config = base().network(NetworkPolicy::Deny).build();
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
    let config = base().ipc(IpcPolicy::Strict).build();
    let status = run(&config, &["shm"]);
    let v = explain(&config, status).expect("should diagnose a violation");
    assert_eq!(v.kind, ViolationKind::Seccomp);
}

#[test]
fn cpu_limit_is_diagnosed_as_resource_limit() {
    let config = base().cpu_time_limit_secs(1).build();
    let status = run(&config, &["spin"]);
    let v = explain(&config, status).expect("should diagnose a violation");
    assert_eq!(v.kind, ViolationKind::ResourceLimit);
}

#[test]
fn violation_display_includes_summary_and_suggestions() {
    let config = base().network(NetworkPolicy::Deny).build();
    let status = run(&config, &["socket-inet"]);
    let v = explain(&config, status).unwrap();
    let rendered = v.to_string();
    assert!(rendered.contains("SIGSYS"));
    assert!(
        rendered.contains("  - "),
        "Display should bullet the suggestions"
    );
}
