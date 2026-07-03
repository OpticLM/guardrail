#![allow(dead_code)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use guardrail_core::{FsAccess, SandboxBuilder};

pub fn probe_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_guardrail-macos-probe"))
}

pub fn probe(args: &[&str]) -> Command {
    let mut command = Command::new(probe_path());
    command.args(args);
    command
}

/// Base grants required to execute the test probe under Seatbelt.
///
/// These are explicit test grants, not backend defaults: every filesystem path
/// allowed here is visible in the resulting `SandboxConfig`.
pub fn base() -> SandboxBuilder {
    let mut builder = SandboxBuilder::new().darwin_sandbox_profiles([runtime_profile()]);
    for dir in runtime_dirs() {
        builder = builder.fs([
            FsAccess::ReadAllow(dir.clone()),
            FsAccess::ExecuteAllow(dir),
        ]);
    }
    builder
}

pub fn read_only_base() -> SandboxBuilder {
    let mut builder = SandboxBuilder::new().darwin_sandbox_profiles([runtime_profile()]);
    for dir in runtime_dirs() {
        builder = builder.fs([FsAccess::ReadAllow(dir)]);
    }
    builder
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
