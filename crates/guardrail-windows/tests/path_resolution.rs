#![cfg(windows)]

//! Regression coverage for issue #23: bare program names must resolve against
//! the configured sandbox `PATH`, never the supervisor's lookup context.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use guardrail_core::{
    Backend, Error, FsAccess, IpcPolicy, NetworkPolicy, ResourceLimits, SandboxCommand,
    SandboxConfig, StdioMode, UserNamespacePolicy,
};
use guardrail_windows::WindowsBackend;

static COUNTER: AtomicU64 = AtomicU64::new(1);

fn probe_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_guardrail-windows-probe"))
}

fn spawn_child(config: &SandboxConfig, command: SandboxCommand) -> guardrail_core::SandboxChild {
    WindowsBackend::new(config.clone())
        .expect("backend")
        .spawn(command)
        .expect("spawn")
}

#[test]
fn bare_name_resolves_from_the_configured_path() {
    let temp = TempPath::new();
    fs::create_dir_all(temp.path()).expect("create temp dir");
    // A name the parent's own PATH cannot supply.
    let copied = temp.path().join("guardrail-issue23-probe.exe");
    fs::copy(probe_path(), &copied).expect("copy probe into the configured PATH");

    let mut config = config_with_runtime_env("bare-name");
    config.fs.push(FsAccess::ReadAllow(temp.path().into()));
    config
        .env
        .insert("PATH".into(), temp.path().display().to_string());
    config
        .env
        .insert("GUARDRAIL_PATH_MARKER".into(), "configured".into());

    let mut command = SandboxCommand::new("guardrail-issue23-probe");
    command.args = vec![
        "check-env".into(),
        "GUARDRAIL_PATH_MARKER".into(),
        "configured".into(),
    ];

    let mut child = spawn_child(&config, command);
    let status = child.wait().expect("wait");

    assert!(
        status.success(),
        "a bare name present only in the configured PATH must spawn: {status:?}"
    );
}

#[test]
fn configured_path_shadows_the_parent_lookup_context() {
    let temp = TempPath::new();
    fs::create_dir_all(temp.path()).expect("create temp dir");
    // The parent context resolves `cmd` to System32's cmd.exe; the configured
    // PATH supplies the probe under the same name and must win.
    fs::copy(probe_path(), temp.path().join("cmd.exe")).expect("copy probe as cmd.exe");

    let mut config = config_with_runtime_env("shadow");
    config.fs.push(FsAccess::ReadAllow(temp.path().into()));
    config
        .env
        .insert("PATH".into(), temp.path().display().to_string());
    config
        .env
        .insert("GUARDRAIL_SHADOW".into(), "configured-cmd".into());

    let mut command = SandboxCommand::new("cmd");
    command.args = vec!["echo-env".into(), "GUARDRAIL_SHADOW".into()];
    // A real cmd.exe launched with these arguments would read stdin
    // interactively; give it EOF so a regression fails fast instead of
    // hanging the test.
    command.stdin = StdioMode::Null;
    command.stdout = StdioMode::Piped;

    let child = spawn_child(&config, command);
    let output = child.wait_with_output().expect("wait with output");

    assert!(output.status.success(), "probe-as-cmd failed: {output:?}");
    assert_eq!(
        output.stdout, b"configured-cmd",
        "the executable from the configured PATH must run, not the parent context's cmd.exe"
    );
}

#[test]
fn missing_bare_name_is_a_not_found_spawn_error() {
    let config = config_with_runtime_env("missing");
    let command = SandboxCommand::new("guardrail-issue23-missing");

    let err = WindowsBackend::new(config)
        .expect("backend")
        .spawn(command)
        .expect_err("a bare name absent from the configured PATH must not spawn");

    match err {
        Error::Spawn(io) => assert_eq!(io.kind(), std::io::ErrorKind::NotFound, "{io:?}"),
        other => panic!("expected a NotFound spawn error, got {other:?}"),
    }
}

#[test]
fn relative_configured_path_is_an_invalid_input_spawn_error() {
    let mut config = config_with_runtime_env("relative");
    config.env.insert("PATH".into(), ".".into());
    let command = SandboxCommand::new("guardrail-issue23-probe");

    let err = WindowsBackend::new(config)
        .expect("backend")
        .spawn(command)
        .expect_err("a relative configured PATH must not consult the supervisor cwd");

    match err {
        Error::Spawn(io) => assert_eq!(io.kind(), std::io::ErrorKind::InvalidInput, "{io:?}"),
        other => panic!("expected an InvalidInput spawn error, got {other:?}"),
    }
}

#[test]
fn explicit_program_paths_spawn_without_a_configured_path() {
    let mut config = config_with_runtime_env("explicit");
    config.fs.push(FsAccess::ReadAllow(
        probe_path()
            .parent()
            .expect("probe binary has a parent directory")
            .into(),
    ));
    let mut command = SandboxCommand::new(env!("CARGO_BIN_EXE_guardrail-windows-probe"));
    command.args = vec!["echo-stdio".into()];

    let mut child = spawn_child(&config, command);
    let status = child.wait().expect("wait");

    assert!(
        status.success(),
        "an explicit program path needs no sandbox PATH: {status:?}"
    );
}

/// The standard runtime variables AppContainer launches need — deliberately
/// without `PATH`, so each test states the lookup context it grants.
fn config_with_runtime_env(label: &str) -> SandboxConfig {
    let mut env = BTreeMap::new();
    for key in ["SystemRoot", "LOCALAPPDATA", "USERPROFILE", "TEMP", "TMP"] {
        if let Ok(value) = std::env::var(key) {
            env.insert(key.to_string(), value);
        }
    }
    SandboxConfig {
        fs: vec![],
        network: NetworkPolicy::Deny,
        linux_ipc: IpcPolicy::Strict,
        linux_unix_sockets: vec![],
        limits: ResourceLimits::default(),
        env,
        darwin_sandbox_profiles: vec![],
        linux_user_namespaces: UserNamespacePolicy::Deny,
        windows_cache_namespace: Some(unique_namespace(label)),
    }
}

fn unique_namespace(label: &str) -> String {
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!(
        "guardrail-windows-path-{label}-{}-{counter}",
        std::process::id()
    )
}

struct TempPath {
    path: PathBuf,
}

impl TempPath {
    fn new() -> Self {
        let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "guardrail-windows-path-{}-{counter}",
            std::process::id()
        ));
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempPath {
    fn drop(&mut self) {
        // Best-effort cleanup; a leftover temp dir must not fail the test.
        let _removed = fs::remove_dir_all(&self.path);
    }
}
