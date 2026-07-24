#![allow(dead_code)]

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use guardrail_core::{
    FsAccess, NetworkPolicy, ResourceLimits, SandboxCommand, SandboxConfig, UserNamespacePolicy,
};

pub fn probe_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_guardrail-macos-probe"))
}

pub fn probe(args: &[&str]) -> SandboxCommand {
    let mut command = SandboxCommand::new(probe_path());
    command.args = args.iter().copied().map(Into::into).collect();
    command
}

/// Base grants required to execute the test probe under Seatbelt.
///
/// These are explicit test grants, not backend defaults: every filesystem path
/// allowed here is visible in the resulting `SandboxConfig`.
pub fn base() -> SandboxConfig {
    let mut fs = Vec::new();
    for dir in runtime_dirs() {
        fs.push(FsAccess::ReadAllow(dir.clone()));
        fs.push(FsAccess::ExecuteAllow(dir));
    }
    SandboxConfig {
        fs,
        network: NetworkPolicy::Deny,
        linux_unix_sockets: vec![],
        limits: ResourceLimits::default(),
        env: BTreeMap::new(),
        darwin_sandbox_profiles: vec![runtime_profile()],
        linux_user_namespaces: UserNamespacePolicy::Deny,
        windows_cache_namespace: None,
            windows_manifest_dir: None,
            windows_acl_verification: guardrail_core::WindowsAclVerification::default(),
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
        linux_unix_sockets: vec![],
        limits: ResourceLimits::default(),
        env: BTreeMap::new(),
        darwin_sandbox_profiles: vec![runtime_profile()],
        linux_user_namespaces: UserNamespacePolicy::Deny,
        windows_cache_namespace: None,
            windows_manifest_dir: None,
            windows_acl_verification: guardrail_core::WindowsAclVerification::default(),
    }
}

fn runtime_profile() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("runtime.sb")
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

fn runtime_library_paths(exe: &Path) -> Vec<PathBuf> {
    let output = match Command::new("otool").arg("-L").arg(exe).output() {
        Ok(output) if output.status.success() => output,
        _ => return Vec::new(),
    };

    String::from_utf8_lossy(&output.stdout)
        .lines()
        .skip(1)
        .filter_map(|line| line.split_whitespace().next())
        .filter(|token| token.starts_with('/'))
        .map(PathBuf::from)
        .filter(|path| path.exists())
        .collect()
}

fn add_dir_and_canonical(dirs: &mut BTreeSet<PathBuf>, dir: &Path) {
    dirs.insert(dir.to_path_buf());
    if let Ok(canonical) = std::fs::canonicalize(dir) {
        dirs.insert(canonical);
    }
}
