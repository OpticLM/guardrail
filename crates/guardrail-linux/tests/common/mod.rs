#![allow(dead_code)]

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use guardrail_core::{FsAccess, IpcPolicy, NetworkPolicy, ResourceLimits, SandboxConfig};

pub fn probe_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_guardrail-probe"))
}

pub fn probe_command() -> Command {
    Command::new(probe_path())
}

pub fn probe(args: &[&str]) -> Command {
    let mut c = probe_command();
    c.args(args).stdout(Stdio::null()).stderr(Stdio::null());
    c
}

/// Base grants required to execute the test probe under Landlock.
///
/// These are explicit test grants, not backend defaults: the caller can inspect
/// the resulting `SandboxConfig` and see every filesystem path being allowed.
pub fn base() -> SandboxConfig {
    let mut fs = Vec::new();
    for dir in runtime_dirs() {
        fs.push(FsAccess::ReadAllow(dir.clone()));
        fs.push(FsAccess::ExecuteAllow(dir));
    }
    SandboxConfig {
        fs,
        network: NetworkPolicy::Deny,
        linux_ipc: IpcPolicy::Strict,
        limits: ResourceLimits::default(),
        env: BTreeMap::new(),
        darwin_sandbox_profiles: vec![],
        windows_cache_namespace: None,
    }
}

pub fn read_only_base() -> SandboxConfig {
    let mut fs = Vec::new();
    for dir in runtime_dirs() {
        fs.push(FsAccess::ReadAllow(dir));
    }
    SandboxConfig {
        fs,
        network: NetworkPolicy::Deny,
        linux_ipc: IpcPolicy::Strict,
        limits: ResourceLimits::default(),
        env: BTreeMap::new(),
        darwin_sandbox_profiles: vec![],
        windows_cache_namespace: None,
    }
}

fn runtime_dirs() -> BTreeSet<PathBuf> {
    let exe = probe_path();
    let mut dirs = BTreeSet::new();

    if let Some(dir) = exe.parent() {
        add_dir_and_canonical(&mut dirs, dir);
    }

    for lib in runtime_library_paths(&exe) {
        if let Some(dir) = lib.parent() {
            add_dir_and_canonical(&mut dirs, dir);
        }
    }
    dirs
}

pub fn landlock_enforced() -> bool {
    std::fs::read_to_string("/sys/kernel/security/lsm")
        .map(|s| s.split(',').any(|m| m.trim() == "landlock"))
        .unwrap_or(false)
}

fn runtime_library_paths(exe: &Path) -> Vec<PathBuf> {
    let output = match Command::new("ldd").arg(exe).output() {
        Ok(output) if output.status.success() => output,
        _ => return Vec::new(),
    };

    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .filter_map(|token| {
            let token = token.trim_end_matches(':');
            token.starts_with('/').then(|| PathBuf::from(token))
        })
        .filter(|path| path.exists())
        .collect()
}

fn add_dir_and_canonical(dirs: &mut BTreeSet<PathBuf>, dir: &Path) {
    dirs.insert(dir.to_path_buf());
    if let Ok(canonical) = std::fs::canonicalize(dir) {
        dirs.insert(canonical);
    }
}
