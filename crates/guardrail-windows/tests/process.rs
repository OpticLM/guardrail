#![cfg(windows)]

//! Regression coverage for issue #22: every public [`SandboxChild`] method on
//! a raw-handle Windows child must return its documented result — never panic
//! because of the target OS.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use guardrail_core::{
    Backend, FsAccess, NetworkPolicy, ResourceLimits, SandboxChild, SandboxCommand, SandboxConfig,
    StdioMode, UserNamespacePolicy,
};
use guardrail_windows::WindowsBackend;

static COUNTER: AtomicU64 = AtomicU64::new(1);

fn probe() -> SandboxCommand {
    SandboxCommand::new(env!("CARGO_BIN_EXE_guardrail-windows-probe"))
}

fn probe_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_guardrail-windows-probe"))
        .parent()
        .expect("probe binary has a parent directory")
        .to_path_buf()
}

fn spawn_child(config: &SandboxConfig, command: SandboxCommand) -> SandboxChild {
    WindowsBackend::new(config.clone())
        .expect("backend")
        .spawn(command)
        .expect("spawn")
}

#[test]
fn raw_child_accessors_return_documented_results() {
    let config = config_with_probe_grant();
    let mut command = probe();
    command.args = vec!["echo-stdio".into()];
    command.stdin = StdioMode::Null;
    command.stdout = StdioMode::Null;
    command.stderr = StdioMode::Null;

    let mut child = spawn_child(&config, command);
    assert_ne!(child.id(), 0, "a raw child reports its OS pid");
    assert!(
        child.as_child_mut().is_none(),
        "a raw Windows child wraps no std::process::Child"
    );
    assert!(child.get_stdin().is_none(), "stdin was not piped");
    assert!(child.get_stdout().is_none(), "stdout was not piped");
    assert!(child.get_stderr().is_none(), "stderr was not piped");

    let mut child = child
        .try_into_child()
        .expect_err("a raw Windows child cannot unwrap into a std::process::Child");
    let status = child.wait().expect("wait through the returned handle");
    assert!(status.success(), "echo-stdio failed: {status:?}");
}

#[test]
fn failed_unwrap_returns_a_killable_handle() {
    let config = config_with_probe_grant();
    let mut command = probe();
    command.args = vec!["spin".into()];

    let child = spawn_child(&config, command);
    let mut child = child
        .try_into_child()
        .expect_err("a raw Windows child cannot unwrap into a std::process::Child");
    child.kill().expect("kill through the returned handle");
    let status = child.wait().expect("wait after kill");
    assert!(!status.success(), "a killed spinner must not exit cleanly");
}

fn config_with_probe_grant() -> SandboxConfig {
    let mut env = BTreeMap::new();
    // AppContainer CreateProcess launches need these standard runtime values;
    // they are still explicit config inputs, so parent-only vars stay scrubbed.
    for key in ["SystemRoot", "LOCALAPPDATA", "USERPROFILE", "TEMP", "TMP"] {
        if let Ok(value) = std::env::var(key) {
            env.insert(key.to_string(), value);
        }
    }
    SandboxConfig {
        fs: vec![FsAccess::ReadAllow(probe_dir())],
        network: NetworkPolicy::Deny,
        linux_unix_sockets: vec![],
        limits: ResourceLimits::default(),
        env,
        darwin_sandbox_profiles: vec![],
        linux_user_namespaces: UserNamespacePolicy::Deny,
        windows_cache_namespace: Some(unique_namespace("process")),
        windows_manifest_dir: Some(std::env::temp_dir().join("guardrail-test-manifests")),
        windows_acl_verification: guardrail_core::WindowsAclVerification::default(),
    }
}

fn unique_namespace(label: &str) -> String {
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("guardrail-windows-{label}-{}-{counter}", std::process::id())
}
