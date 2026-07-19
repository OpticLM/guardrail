#![cfg(target_os = "macos")]

//! The launcher receives exactly `SandboxConfig::env`: inherited variables
//! are cleared, while declared variables survive execve.

use guardrail_core::{Backend, StdioMode};
use guardrail_macos::MacosBackend;

mod common;

#[test]
fn inherited_environment_is_cleared() {
    // A variable set in the parent must NOT reach the child; a
    // `SandboxCommand` cannot even carry command-local variables.
    // SAFETY: single-threaded test setup before any spawn.
    unsafe { std::env::set_var("GUARDRAIL_SECRET", "leaked") };

    let config = common::base();
    let mut command = common::probe(&["echo-env", "GUARDRAIL_SECRET"]);
    command.stdout = StdioMode::Piped;

    let child = MacosBackend::new(config)
        .expect("backend")
        .spawn(command)
        .expect("spawn");
    let output = child.wait_with_output().expect("wait");

    assert!(output.status.success());
    assert_eq!(output.stdout, b"");
}

#[test]
fn configured_environment_reaches_the_child() {
    let mut config = common::base();
    config.env.insert("GREETING".into(), "hello".into());
    let mut command = common::probe(&["echo-env", "GREETING"]);
    command.stdout = StdioMode::Piped;

    let child = MacosBackend::new(config)
        .expect("backend")
        .spawn(command)
        .expect("spawn");
    let output = child.wait_with_output().expect("wait");

    assert!(output.status.success());
    assert_eq!(output.stdout, b"hello");
}
