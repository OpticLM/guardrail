#![cfg(windows)]

use std::path::PathBuf;
use std::process::Command;

use guardrail_core::{FsAccess, SandboxBuilder};
use guardrail_windows::WindowsBackend;

fn probe() -> Command {
    Command::new(env!("CARGO_BIN_EXE_guardrail-windows-probe"))
}

fn probe_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_guardrail-windows-probe"))
        .parent()
        .expect("probe binary has a parent directory")
        .to_path_buf()
}

#[test]
fn inherited_env_is_cleared() {
    // SAFETY: this test sets a single process variable before spawning the
    // sandboxed child and does not read it concurrently.
    unsafe { std::env::set_var("GUARDRAIL_SECRET", "leaked") };

    let config = builder_with_windows_runtime_env()
        .fs([FsAccess::ReadAllow(probe_dir())])
        .build();
    let mut command = probe();
    command.args(["check-env", "GUARDRAIL_SECRET", "leaked"]);

    let mut child = config
        .spawn_with(&WindowsBackend::new(), command)
        .expect("spawn probe");
    let status = child.wait().expect("wait");

    assert!(
        !status.success(),
        "inherited env var must not reach the sandboxed child"
    );
}

#[test]
fn explicitly_added_env_reaches_child() {
    let config = builder_with_windows_runtime_env()
        .fs([FsAccess::ReadAllow(probe_dir())])
        .env("GREETING", "hello")
        .build();
    let mut command = probe();
    command.args(["check-env", "GREETING", "hello"]);

    let mut child = config
        .spawn_with(&WindowsBackend::new(), command)
        .expect("spawn probe");
    let status = child.wait().expect("wait");

    assert!(status.success(), "explicit env var should reach the child");
}

fn builder_with_windows_runtime_env() -> SandboxBuilder {
    let mut builder = SandboxBuilder::new();
    // AppContainer CreateProcess launches need these standard runtime values;
    // they are still explicit builder inputs, so parent-only vars stay scrubbed.
    for key in ["SystemRoot", "LOCALAPPDATA", "USERPROFILE", "TEMP", "TMP"] {
        if let Ok(value) = std::env::var(key) {
            builder = builder.env(key, value);
        }
    }
    builder
}
