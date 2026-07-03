use std::path::{Component, Path, PathBuf};

use guardrail_core::{FsAccess, IpcPolicy, NetworkPolicy, SandboxConfig};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SeatbeltProfile {
    pub(crate) source: String,
}

pub(crate) fn build(config: &SandboxConfig) -> SeatbeltProfile {
    build_with_imports(config, &[])
}

pub(crate) fn build_with_imports(
    config: &SandboxConfig,
    imports: &[std::path::PathBuf],
) -> SeatbeltProfile {
    let mut source = String::from("(version 1)\n");

    for path in imports {
        let path = sbpl_string(path);
        source.push_str(&format!("(import \"{path}\")\n"));
    }

    source.push_str(&build_policy_rules(config));
    SeatbeltProfile { source }
}

pub(crate) fn build_policy_rules(config: &SandboxConfig) -> String {
    let mut source = String::from("(deny default)\n(debug deny)\n");

    for (index, rule) in config.fs.iter().enumerate() {
        let later_rules = &config.fs[index + 1..];
        match rule {
            FsAccess::ReadAllow(path) => {
                let exclusions = read_deny_paths(later_rules);
                push_path_rules(&mut source, "allow", &["file-read*"], path, &exclusions);
            }
            FsAccess::ReadDeny(path) => {
                let exclusions = read_allow_paths(later_rules);
                push_path_rules(&mut source, "deny", &["file-read*"], path, &exclusions);
            }
            FsAccess::WriteAllow(path) => {
                let exclusions = write_deny_paths(later_rules);
                push_path_rules(&mut source, "allow", &["file-write*"], path, &exclusions);
            }
            FsAccess::WriteDeny(path) => {
                let exclusions = write_allow_paths(later_rules);
                push_path_rules(&mut source, "deny", &["file-write*"], path, &exclusions);
            }
            FsAccess::ExecuteAllow(path) => {
                let exclusions = execute_deny_paths(later_rules);
                push_path_rules(
                    &mut source,
                    "allow",
                    &["file-map-executable", "process-exec*"],
                    path,
                    &exclusions,
                );
            }
            FsAccess::ExecuteDeny(path) => {
                let exclusions = execute_allow_paths(later_rules);
                push_path_rules(
                    &mut source,
                    "deny",
                    &["file-map-executable", "process-exec*"],
                    path,
                    &exclusions,
                );
            }
        }
    }

    match config.network {
        NetworkPolicy::Deny => {}
        NetworkPolicy::OutboundOnly => {
            source.push_str("(allow network-outbound)\n");
            source.push_str("(allow system-socket)\n");
        }
        NetworkPolicy::Full => {
            source.push_str("(allow network*)\n");
            source.push_str("(allow system-socket)\n");
        }
    }

    match config.ipc {
        IpcPolicy::Strict => {}
        IpcPolicy::Relaxed => {
            // Keep this intentionally narrow until plan 010 validates the exact
            // Seatbelt operations on macOS. Custom `.sb` profile imports are
            // the escape hatch for workloads that need more IPC.
        }
    }

    source
}

fn push_path_rules(
    source: &mut String,
    action: &str,
    operations: &[&str],
    path: &Path,
    exclusions: &[PathBuf],
) {
    for path in path_variants(path) {
        push_path_rule(source, action, operations, &path, exclusions);
    }
}

fn push_path_rule(
    source: &mut String,
    action: &str,
    operations: &[&str],
    path: &Path,
    exclusions: &[PathBuf],
) {
    for operation in operations {
        source.push_str(&format!("({action} {operation} "));
        push_subpath_filter(source, path, exclusions);
        source.push_str(")\n");
    }
}

fn push_subpath_filter(source: &mut String, path: &Path, exclusions: &[PathBuf]) {
    if exclusions.is_empty() {
        source.push_str("(subpath \"");
        source.push_str(&sbpl_string(path));
        source.push_str("\")");
        return;
    }

    source.push_str("(require-all (subpath \"");
    source.push_str(&sbpl_string(path));
    source.push_str("\")");
    for exclusion in exclusions {
        source.push_str(" (require-not (subpath \"");
        source.push_str(&sbpl_string(exclusion));
        source.push_str("\"))");
    }
    source.push(')');
}

fn read_allow_paths(rules: &[FsAccess]) -> Vec<PathBuf> {
    rules
        .iter()
        .flat_map(|rule| match rule {
            FsAccess::ReadAllow(path) => path_variants(path),
            _ => Vec::new(),
        })
        .collect()
}

fn read_deny_paths(rules: &[FsAccess]) -> Vec<PathBuf> {
    rules
        .iter()
        .flat_map(|rule| match rule {
            FsAccess::ReadDeny(path) => path_variants(path),
            _ => Vec::new(),
        })
        .collect()
}

fn write_allow_paths(rules: &[FsAccess]) -> Vec<PathBuf> {
    rules
        .iter()
        .flat_map(|rule| match rule {
            FsAccess::WriteAllow(path) => path_variants(path),
            _ => Vec::new(),
        })
        .collect()
}

fn write_deny_paths(rules: &[FsAccess]) -> Vec<PathBuf> {
    rules
        .iter()
        .flat_map(|rule| match rule {
            FsAccess::WriteDeny(path) => path_variants(path),
            _ => Vec::new(),
        })
        .collect()
}

fn execute_allow_paths(rules: &[FsAccess]) -> Vec<PathBuf> {
    rules
        .iter()
        .flat_map(|rule| match rule {
            FsAccess::ExecuteAllow(path) => path_variants(path),
            _ => Vec::new(),
        })
        .collect()
}

fn execute_deny_paths(rules: &[FsAccess]) -> Vec<PathBuf> {
    rules
        .iter()
        .flat_map(|rule| match rule {
            FsAccess::ExecuteDeny(path) => path_variants(path),
            _ => Vec::new(),
        })
        .collect()
}

fn path_variants(path: &Path) -> Vec<PathBuf> {
    let original = path.to_path_buf();
    let canonical = canonical_path(path);
    let mut paths = vec![original.clone()];

    if let Some(canonical) = canonical
        && canonical != original
    {
        paths.push(canonical);
    }

    paths
}

fn canonical_path(path: &Path) -> Option<PathBuf> {
    if let Ok(canonical) = std::fs::canonicalize(path) {
        return Some(canonical);
    }

    if !path.is_absolute() {
        return None;
    }

    for ancestor in path.ancestors().skip(1) {
        let Ok(canonical_ancestor) = std::fs::canonicalize(ancestor) else {
            continue;
        };
        let suffix = path.strip_prefix(ancestor).ok()?;
        if suffix.components().all(|component| {
            matches!(
                component,
                Component::Normal(_) | Component::CurDir | Component::ParentDir
            )
        }) {
            return Some(canonical_ancestor.join(suffix));
        }
    }

    None
}

pub(crate) fn sbpl_string(path: &Path) -> String {
    path.display()
        .to_string()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use guardrail_core::{NetworkPolicy, SandboxBuilder};

    use super::*;

    #[test]
    fn default_config_denies_by_default() {
        let profile = build(&SandboxBuilder::new().build());

        assert_eq!(
            profile.source,
            "(version 1)\n(deny default)\n(debug deny)\n"
        );
    }

    #[test]
    fn imported_profiles_are_emitted_before_generated_rules() {
        let profile = build_with_imports(
            &SandboxBuilder::new()
                .fs([FsAccess::ReadAllow("/tmp/in".into())])
                .build(),
            &[
                std::path::PathBuf::from("/tmp/base-one.sb"),
                std::path::PathBuf::from("/tmp/base-two.sb"),
            ],
        );

        assert_substrings_in_order(
            &profile.source,
            &[
                "(version 1)\n",
                "(import \"/tmp/base-one.sb\")\n",
                "(import \"/tmp/base-two.sb\")\n",
                "(deny default)\n",
                "(debug deny)\n",
                "(allow file-read* (subpath \"/tmp/in\"))\n",
            ],
        );
    }

    #[test]
    fn import_paths_are_escaped() {
        let profile = build_with_imports(
            &SandboxBuilder::new().build(),
            &[std::path::PathBuf::from(r#"/tmp/base"name\with-slash.sb"#)],
        );

        assert!(
            profile
                .source
                .contains(r#"(import "/tmp/base\"name\\with-slash.sb")"#)
        );
    }

    #[test]
    fn read_access_emits_file_read_subpath_rule() {
        let profile = build(
            &SandboxBuilder::new()
                .fs([FsAccess::ReadAllow("/tmp/in".into())])
                .build(),
        );

        assert!(profile.source.contains("(version 1)\n"));
        assert!(
            profile
                .source
                .contains("(allow file-read* (subpath \"/tmp/in\"))\n")
        );
    }

    #[cfg(unix)]
    #[test]
    fn filesystem_rules_emit_canonical_path_alias() {
        let root = std::env::temp_dir().join(format!(
            "guardrail-macos-profile-alias-{}-{}",
            std::process::id(),
            unique_suffix()
        ));
        let real = root.join("real");
        let alias = root.join("alias");
        let future_alias = alias.join("future.txt");
        let future_real = real.join("future.txt");
        std::fs::create_dir_all(&real).unwrap();
        std::os::unix::fs::symlink(&real, &alias).unwrap();

        let profile = build(
            &SandboxBuilder::new()
                .fs([FsAccess::ReadAllow(future_alias.clone())])
                .build(),
        );

        assert!(profile.source.contains(&format!(
            "(allow file-read* (subpath \"{}\"))\n",
            sbpl_string(&future_alias)
        )));
        assert!(profile.source.contains(&format!(
            "(allow file-read* (subpath \"{}\"))\n",
            sbpl_string(&canonical_test_path(&future_real))
        )));

        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn filesystem_rule_exclusions_emit_canonical_path_alias() {
        let root = std::env::temp_dir().join(format!(
            "guardrail-macos-profile-exclusion-alias-{}-{}",
            std::process::id(),
            unique_suffix()
        ));
        let real = root.join("real");
        let alias = root.join("alias");
        let secret_alias = alias.join("secret");
        let secret_real = real.join("secret");
        std::fs::create_dir_all(&real).unwrap();
        std::os::unix::fs::symlink(&real, &alias).unwrap();

        let profile = build(
            &SandboxBuilder::new()
                .fs([
                    FsAccess::ReadAllow(alias.clone()),
                    FsAccess::ReadDeny(secret_alias.clone()),
                ])
                .build(),
        );

        assert!(profile.source.contains(&format!(
            "(require-not (subpath \"{}\"))",
            sbpl_string(&secret_alias)
        )));
        assert!(profile.source.contains(&format!(
            "(require-not (subpath \"{}\"))",
            sbpl_string(&canonical_test_path(&secret_real))
        )));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn read_deny_emits_file_read_deny_rule() {
        let profile = build(
            &SandboxBuilder::new()
                .fs([FsAccess::ReadDeny("/tmp/secret".into())])
                .build(),
        );

        assert!(
            profile
                .source
                .contains("(deny file-read* (subpath \"/tmp/secret\"))\n")
        );
    }

    #[test]
    fn write_access_emits_only_file_write_subpath_rule() {
        let profile = build(
            &SandboxBuilder::new()
                .fs([FsAccess::WriteAllow("/tmp/work".into())])
                .build(),
        );

        assert!(!profile.source.contains("(allow file-read*"));
        assert!(
            profile
                .source
                .contains("(allow file-write* (subpath \"/tmp/work\"))\n")
        );
    }

    #[test]
    fn write_deny_emits_only_file_write_deny_rule() {
        let profile = build(
            &SandboxBuilder::new()
                .fs([FsAccess::WriteDeny("/tmp/work".into())])
                .build(),
        );

        assert!(!profile.source.contains("(deny file-read*"));
        assert!(
            profile
                .source
                .contains("(deny file-write* (subpath \"/tmp/work\"))\n")
        );
    }

    #[test]
    fn execute_access_emits_only_executable_rules() {
        let profile = build(
            &SandboxBuilder::new()
                .fs([FsAccess::ExecuteAllow("/tmp/bin".into())])
                .build(),
        );

        assert!(!profile.source.contains("(allow file-read*"));
        assert!(
            profile
                .source
                .contains("(allow file-map-executable (subpath \"/tmp/bin\"))\n")
        );
        assert!(
            profile
                .source
                .contains("(allow process-exec* (subpath \"/tmp/bin\"))\n")
        );
    }

    #[test]
    fn execute_deny_emits_only_executable_deny_rules() {
        let profile = build(
            &SandboxBuilder::new()
                .fs([FsAccess::ExecuteDeny("/tmp/bin".into())])
                .build(),
        );

        assert!(!profile.source.contains("(deny file-read*"));
        assert!(
            profile
                .source
                .contains("(deny file-map-executable (subpath \"/tmp/bin\"))\n")
        );
        assert!(
            profile
                .source
                .contains("(deny process-exec* (subpath \"/tmp/bin\"))\n")
        );
    }

    #[test]
    fn mixed_filesystem_rules_preserve_declaration_order() {
        let profile = build(
            &SandboxBuilder::new()
                .fs([
                    FsAccess::ReadAllow("/tmp".into()),
                    FsAccess::ReadDeny("/tmp/secret".into()),
                    FsAccess::ReadAllow("/tmp/secret/public.txt".into()),
                    FsAccess::WriteAllow("/tmp/out".into()),
                ])
                .build(),
        );

        assert_substrings_in_order(
            &profile.source,
            &[
                "(version 1)\n",
                "(deny default)\n",
                "(debug deny)\n",
                "(allow file-read* (require-all (subpath \"/tmp\")",
                "(require-not (subpath \"/tmp/secret\"))",
                "(deny file-read* (require-all (subpath \"/tmp/secret\")",
                "(require-not (subpath \"/tmp/secret/public.txt\"))",
                "(allow file-read* (subpath \"/tmp/secret/public.txt\"))\n",
                "(allow file-write* (subpath \"/tmp/out\"))\n",
            ],
        );
    }

    #[test]
    fn deny_network_emits_no_network_rule() {
        let profile = build(&SandboxBuilder::new().network(NetworkPolicy::Deny).build());

        assert!(!profile.source.contains("network"));
    }

    #[test]
    fn outbound_network_emits_network_outbound_rule() {
        let profile = build(
            &SandboxBuilder::new()
                .network(NetworkPolicy::OutboundOnly)
                .build(),
        );

        assert!(profile.source.contains("(allow network-outbound)\n"));
        assert!(profile.source.contains("(allow system-socket)\n"));
    }

    #[test]
    fn full_network_emits_network_star_rule() {
        let profile = build(&SandboxBuilder::new().network(NetworkPolicy::Full).build());

        assert!(profile.source.contains("(allow network*)\n"));
        assert!(profile.source.contains("(allow system-socket)\n"));
    }

    #[test]
    fn double_quotes_in_paths_are_escaped() {
        let profile = build(
            &SandboxBuilder::new()
                .fs([FsAccess::ReadAllow(r#"/tmp/name"with-quote"#.into())])
                .build(),
        );

        assert!(
            profile
                .source
                .contains(r#"(subpath "/tmp/name\"with-quote")"#)
        );
    }

    #[test]
    fn backslashes_in_paths_are_escaped() {
        let profile = build(
            &SandboxBuilder::new()
                .fs([FsAccess::ReadAllow(r"/tmp/name\with-slash".into())])
                .build(),
        );

        assert!(
            profile
                .source
                .contains(r#"(subpath "/tmp/name\\with-slash")"#)
        );
    }

    #[cfg(unix)]
    fn unique_suffix() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    }

    #[cfg(unix)]
    fn canonical_test_path(path: &Path) -> PathBuf {
        canonical_path(path).unwrap_or_else(|| path.to_path_buf())
    }

    fn assert_substrings_in_order(haystack: &str, needles: &[&str]) {
        let mut offset = 0;
        for needle in needles {
            let Some(index) = haystack[offset..].find(needle) else {
                panic!("missing {needle:?} after byte {offset} in:\n{haystack}");
            };
            offset += index + needle.len();
        }
    }
}
