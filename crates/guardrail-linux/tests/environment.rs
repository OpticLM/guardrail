#![cfg(target_os = "linux")]

//! Verifies the §3 "unconditional env scrub": the child sees ONLY the env vars
//! added to the builder, never the parent's inherited ones.

use std::process::Command;

use guardrail_linux::LinuxBackend;

fn probe() -> Command {
    common::probe_command()
}

mod common;

#[test]
fn inherited_env_is_cleared() {
    // A variable set in the parent must NOT reach the child.
    // SAFETY: single-threaded test setup before any spawn.
    unsafe { std::env::set_var("GUARDRAIL_SECRET", "leaked") };

    let config = common::base().build();
    let mut cmd = probe();
    cmd.arg("echo-env").arg("GUARDRAIL_SECRET");
    cmd.stdout(std::process::Stdio::piped());

    let child = config.spawn_with(&LinuxBackend::new(), cmd).expect("spawn");
    let out = child.into_inner().wait_with_output().expect("wait");
    assert!(out.status.success());
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "",
        "inherited env var must not reach the sandboxed child"
    );
}

#[test]
fn explicitly_added_env_reaches_child() {
    let config = common::base().env("GREETING", "hello").build();
    let mut cmd = probe();
    cmd.arg("echo-env").arg("GREETING");
    cmd.stdout(std::process::Stdio::piped());

    let child = config.spawn_with(&LinuxBackend::new(), cmd).expect("spawn");
    let out = child.into_inner().wait_with_output().expect("wait");
    assert_eq!(String::from_utf8_lossy(&out.stdout), "hello");
}
