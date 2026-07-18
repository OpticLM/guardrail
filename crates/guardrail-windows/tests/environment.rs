#![cfg(windows)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use guardrail_core::{
    Backend, FsAccess, IpcPolicy, NetworkPolicy, ResourceLimits, SandboxConfig, UserNamespacePolicy,
};
use guardrail_windows::WindowsBackend;

static NAMESPACE_COUNTER: AtomicU64 = AtomicU64::new(1);

fn probe() -> Command {
    Command::new(env!("CARGO_BIN_EXE_guardrail-windows-probe"))
}

fn probe_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_guardrail-windows-probe"))
        .parent()
        .expect("probe binary has a parent directory")
        .to_path_buf()
}

fn spawn_child(config: &SandboxConfig, command: Command) -> guardrail_core::SandboxChild {
    WindowsBackend::new(config.clone())
        .expect("backend")
        .spawn(command)
        .expect("spawn")
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

    let mut child = spawn_child(&config, command);
    let status = child.wait().expect("wait");
    let code = status.code();

    assert_eq!(
        code,
        Some(3),
        "probe did not report the inherited variable absent: {status:?}, code={:#010x}",
        code.unwrap_or_default() as u32
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

    let mut child = spawn_child(&config, command);
    let status = child.wait().expect("wait");
    let code = status.code();

    assert!(
        status.success(),
        "explicit env var should reach the child: {status:?}, code={:#010x}",
        code.unwrap_or_default() as u32
    );
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
        linux_ipc: IpcPolicy::Strict,
        limits: ResourceLimits::default(),
        env,
        darwin_sandbox_profiles: vec![],
        linux_user_namespaces: UserNamespacePolicy::Deny,
        windows_cache_namespace: Some(unique_namespace("environment")),
    }
}

fn unique_namespace(label: &str) -> String {
    let counter = NAMESPACE_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("guardrail-windows-{label}-{}-{counter}", std::process::id())
}
