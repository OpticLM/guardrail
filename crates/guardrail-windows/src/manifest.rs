//! Per-namespace persistent state for the Windows ACL cache.
//!
//! Each cache namespace owns a directory (default
//! `%LOCALAPPDATA%\guardrail\<namespace>`, overridable via
//! `SandboxConfig::windows_manifest_dir`) holding:
//!
//! * `manifest` — the canonical filesystem rules whose ACEs are currently
//!   applied on disk. Written after every successful application; read on the
//!   next run to decide between "verify only", "apply a set-diff", or "rebuild
//!   from scratch".
//! * `active` — an advisory cross-process marker. Every live sandbox holds an
//!   open handle without `FILE_SHARE_DELETE`; a process wanting to change the
//!   namespace's policy probes by deleting the file. Deletion succeeding means
//!   no other process is using the namespace; failing with a sharing violation
//!   means the namespace is active elsewhere, so a *different* policy is
//!   rejected while an identical one attaches alongside.
//!
//! The manifest format is a plain line list (`allow|deny <right> <path>`)
//! with a version header — deliberately no structured-format dependency.

#![cfg(windows)]

use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use guardrail_core::SandboxConfig;

use crate::acl::{FsRight, Rule, RuleEffect};

const MANIFEST_HEADER: &str = "guardrail-windows-manifest v1";
const FILE_SHARE_READ_WRITE: u32 = 0x1 | 0x2;

/// The directory holding this namespace's manifest and active marker.
pub(crate) fn namespace_dir(
    config: &SandboxConfig,
    sanitized_namespace: &str,
) -> io::Result<PathBuf> {
    let base = match &config.windows_manifest_dir {
        Some(dir) => dir.clone(),
        None => {
            let local = std::env::var_os("LOCALAPPDATA").ok_or_else(|| {
                io::Error::other(
                    "LOCALAPPDATA is not set and windows_manifest_dir is not configured",
                )
            })?;
            PathBuf::from(local).join("guardrail")
        }
    };
    Ok(base.join(sanitized_namespace))
}

/// Read the previously-applied canonical rules. `Ok(None)` when no manifest
/// exists or it cannot be parsed — both mean "rebuild from scratch".
pub(crate) fn load(dir: &Path) -> io::Result<Option<Vec<Rule>>> {
    let mut text = String::new();
    match File::open(dir.join("manifest")) {
        Ok(mut file) => file.read_to_string(&mut text)?,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    };

    let mut lines = text.lines();
    if lines.next() != Some(MANIFEST_HEADER) {
        return Ok(None);
    }
    let mut rules = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some(rule) = parse_line(line) else {
            return Ok(None);
        };
        rules.push(rule);
    }
    Ok(Some(rules))
}

/// Persist the canonical rules that are now applied on disk.
pub(crate) fn store(dir: &Path, rules: &[Rule]) -> io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let mut text = String::from(MANIFEST_HEADER);
    text.push('\n');
    for rule in rules {
        let effect = match rule.effect {
            RuleEffect::Allow => "allow",
            RuleEffect::Deny => "deny",
        };
        let right = match rule.right {
            FsRight::Read => "read",
            FsRight::Write => "write",
            FsRight::Execute => "execute",
        };
        let Some(path) = rule.path.to_str() else {
            return Err(io::Error::other(format!(
                "rule path is not valid Unicode: {}",
                rule.path.display()
            )));
        };
        text.push_str(&format!("{effect} {right} {path}\n"));
    }
    // Write-then-rename so a crash never leaves a truncated manifest.
    let staging = dir.join("manifest.new");
    std::fs::write(&staging, text)?;
    std::fs::rename(&staging, dir.join("manifest"))
}

fn parse_line(line: &str) -> Option<Rule> {
    let (effect, rest) = line.split_once(' ')?;
    let (right, path) = rest.split_once(' ')?;
    let effect = match effect {
        "allow" => RuleEffect::Allow,
        "deny" => RuleEffect::Deny,
        _ => return None,
    };
    let right = match right {
        "read" => FsRight::Read,
        "write" => FsRight::Write,
        "execute" => FsRight::Execute,
        _ => return None,
    };
    if path.is_empty() {
        return None;
    }
    Some(Rule {
        path: PathBuf::from(path),
        right,
        effect,
    })
}

/// A held cross-process activity marker for a namespace.
#[derive(Debug)]
pub(crate) struct ActiveMarker {
    _file: File,
}

impl ActiveMarker {
    /// Acquire the marker. `policy_matches_current` receives the manifest that
    /// was current when another process held the namespace; returning `false`
    /// rejects attachment.
    pub(crate) fn acquire(dir: &Path, active_elsewhere_allowed: bool) -> io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let path = dir.join("active");
        // Probe: deleting succeeds only when no other process holds a handle
        // (holders open without FILE_SHARE_DELETE). NotFound is equally idle.
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(_) if active_elsewhere_allowed => {}
            Err(_) => {
                return Err(io::Error::other(
                    "windows_cache_namespace is active in another process with a different filesystem policy",
                ));
            }
        }
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .share_mode(FILE_SHARE_READ_WRITE) // readable by peers, not deletable
            .open(&path)?;
        Ok(Self { _file: file })
    }

    /// Whether any process currently holds the namespace's active marker.
    pub(crate) fn held_elsewhere(dir: &Path) -> bool {
        let path = dir.join("active");
        match std::fs::remove_file(&path) {
            // We deleted an orphaned marker (a previous process died); idle.
            Ok(()) => false,
            Err(err) if err.kind() == io::ErrorKind::NotFound => false,
            Err(_) => true,
        }
    }
}

/// FNV-1a 64 over the canonical rules — stable across processes and releases,
/// unlike `DefaultHasher`.
pub(crate) fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "guardrail-manifest-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn manifest_round_trips() {
        let dir = temp_dir("roundtrip");
        let rules = vec![
            Rule {
                path: PathBuf::from(r"C:\work space"),
                right: FsRight::Write,
                effect: RuleEffect::Allow,
            },
            Rule {
                path: PathBuf::from(r"C:\work space\secret"),
                right: FsRight::Read,
                effect: RuleEffect::Deny,
            },
        ];
        store(&dir, &rules).unwrap();
        assert_eq!(load(&dir).unwrap(), Some(rules));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_or_corrupt_manifest_reads_as_none() {
        let dir = temp_dir("corrupt");
        assert_eq!(load(&dir).unwrap(), None);
        std::fs::write(dir.join("manifest"), "not a manifest\n").unwrap();
        assert_eq!(load(&dir).unwrap(), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn active_marker_blocks_conflicting_and_admits_matching() {
        let dir = temp_dir("marker");
        assert!(!ActiveMarker::held_elsewhere(&dir));
        let held = ActiveMarker::acquire(&dir, false).unwrap();
        assert!(ActiveMarker::held_elsewhere(&dir));
        // A same-policy peer may attach alongside.
        let peer = ActiveMarker::acquire(&dir, true).unwrap();
        // A different-policy peer is rejected while held.
        let err = ActiveMarker::acquire(&dir, false).unwrap_err();
        assert!(err.to_string().contains("different filesystem policy"));
        drop((held, peer));
        assert!(!ActiveMarker::held_elsewhere(&dir));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
