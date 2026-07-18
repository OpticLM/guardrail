#![cfg(target_os = "macos")]

//! The launcher receives exactly `SandboxConfig::env`: command-local and
//! inherited variables are cleared, while declared variables survive execve.

use std::process::Stdio;

use guardrail_core::Backend;
use guardrail_macos::MacosBackend;

mod common;

#[test]
fn command_environment_is_cleared() {
    let config = common::base();
    let mut command = common::probe(&["echo-env", "GUARDRAIL_SECRET"]);
    command
        .env("GUARDRAIL_SECRET", "leaked")
        .stdout(Stdio::piped());

    let child = MacosBackend::new(config)
        .expect("backend")
        .spawn(command)
        .expect("spawn");
    let output = child.into_inner().wait_with_output().expect("wait");

    assert!(output.status.success());
    assert_eq!(output.stdout, b"");
}

#[test]
fn configured_environment_reaches_the_child() {
    let mut config = common::base();
    config.env.insert("GREETING".into(), "hello".into());
    let mut command = common::probe(&["echo-env", "GREETING"]);
    command.stdout(Stdio::piped());

    let child = MacosBackend::new(config)
        .expect("backend")
        .spawn(command)
        .expect("spawn");
    let output = child.into_inner().wait_with_output().expect("wait");

    assert!(output.status.success());
    assert_eq!(output.stdout, b"hello");
}
