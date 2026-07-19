#![cfg(target_os = "linux")]

//! Verifies the §3 "unconditional env scrub": the child sees ONLY the env vars
//! in `SandboxConfig::env`, never the parent's inherited ones.

use guardrail_core::{Backend, StdioMode};
use guardrail_linux::LinuxBackend;

mod common;

#[test]
fn inherited_env_is_cleared() {
    // A variable set in the parent must NOT reach the child.
    // SAFETY: single-threaded test setup before any spawn.
    unsafe { std::env::set_var("GUARDRAIL_SECRET", "leaked") };

    let config = common::base();
    let mut cmd = common::probe_command();
    cmd.args = vec!["echo-env".into(), "GUARDRAIL_SECRET".into()];
    cmd.stdout = StdioMode::Piped;

    let child = LinuxBackend::new(config)
        .expect("backend")
        .spawn(cmd)
        .expect("spawn");
    let out = child.wait_with_output().expect("wait");
    assert!(out.status.success());
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "",
        "inherited env var must not reach the sandboxed child"
    );
}

#[test]
fn explicitly_added_env_reaches_child() {
    let mut config = common::base();
    config.env.insert("GREETING".into(), "hello".into());
    let mut cmd = common::probe_command();
    cmd.args = vec!["echo-env".into(), "GREETING".into()];
    cmd.stdout = StdioMode::Piped;

    let child = LinuxBackend::new(config)
        .expect("backend")
        .spawn(cmd)
        .expect("spawn");
    let out = child.wait_with_output().expect("wait");
    assert_eq!(String::from_utf8_lossy(&out.stdout), "hello");
}
