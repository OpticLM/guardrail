#![cfg(windows)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

use guardrail_core::{Backend, FsAccess, IpcPolicy, NetworkPolicy, ResourceLimits, SandboxConfig};
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

    let mut config = builder_with_windows_runtime_env();
    config.fs.extend([FsAccess::ReadAllow(probe_dir())]);
    let mut command = probe();
    command.args(["check-env", "GUARDRAIL_SECRET", "leaked"]);
    command.env_clear();
    command.envs(&config.env);

    let mut child = WindowsBackend::new()
        .spawn(&config, command)
        .expect("spawn probe");
    let status = child.wait().expect("wait");

    assert!(
        !status.success(),
        "inherited env var must not reach the sandboxed child"
    );
}

#[test]
fn explicitly_added_env_reaches_child() {
    let mut config = builder_with_windows_runtime_env();
    config.fs.extend([FsAccess::ReadAllow(probe_dir())]);
    config.env.insert("GREETING".into(), "hello".into());
    let mut command = probe();
    command.args(["check-env", "GREETING", "hello"]);
    command.env_clear();
    command.envs(&config.env);

    let mut child = WindowsBackend::new()
        .spawn(&config, command)
        .expect("spawn probe");
    let status = child.wait().expect("wait");

    assert!(status.success(), "explicit env var should reach the child");
}

fn builder_with_windows_runtime_env() -> SandboxConfig {
    let mut env = BTreeMap::new();
    // AppContainer CreateProcess launches need these standard runtime values;
    // they are still explicit builder inputs, so parent-only vars stay scrubbed.
    for key in ["SystemRoot", "LOCALAPPDATA", "USERPROFILE", "TEMP", "TMP"] {
        if let Ok(value) = std::env::var(key) {
            env.insert(key.to_string(), value);
        }
    }
    SandboxConfig {
        fs: vec![],
        network: NetworkPolicy::Deny,
        ipc: IpcPolicy::Strict,
        limits: ResourceLimits::default(),
        env,
        darwin_sandbox_profiles: vec![],
    }
}
