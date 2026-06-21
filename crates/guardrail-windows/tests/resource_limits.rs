#![cfg(windows)]

use std::process::Command;

use guardrail_core::SandboxBuilder;
use guardrail_windows::WindowsBackend;

#[test]
fn default_config_runs_command_under_job_object() {
    let config = SandboxBuilder::new().build();
    let mut command = Command::new("cmd");
    command.args(["/C", "exit", "0"]);

    let mut child = config
        .spawn_with(&WindowsBackend::new(), command)
        .expect("spawn under Windows Job Object");
    let status = child.wait().expect("wait");

    assert!(status.success(), "cmd /C exit 0 should succeed");
}

#[test]
#[ignore = "plan 010 adds a deterministic Windows probe for process-tree policy assertions"]
fn max_processes_limit_blocks_child_processes() {
    let config = SandboxBuilder::new().max_processes(1).build();
    let mut command = Command::new("cmd");
    command.args(["/C", "start", "/B", "cmd", "/C", "exit", "0"]);

    let mut child = config
        .spawn_with(&WindowsBackend::new(), command)
        .expect("spawn under Windows Job Object");
    let status = child.wait().expect("wait");

    assert!(
        !status.success(),
        "a max_processes(1) job should not allow a child process"
    );
}
