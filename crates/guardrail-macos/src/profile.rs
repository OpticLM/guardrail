use std::path::{Component, Path, PathBuf};

use guardrail_core::{Error, FsAccess, NetworkPolicy, Result, SandboxConfig};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SeatbeltProfile {
    pub(crate) source: String,
}

pub(crate) fn build(config: &SandboxConfig) -> Result<SeatbeltProfile> {
    build_with_imports(config, &[])
}

pub(crate) fn build_with_imports(
    config: &SandboxConfig,
    imports: &[std::path::PathBuf],
) -> Result<SeatbeltProfile> {
    let mut source = String::from("(version 1)\n");

    for path in imports {
        let path = sbpl_string(path)?;
        source.push_str(&format!("(import \"{path}\")\n"));
    }

    source.push_str(&build_policy_rules(config)?);
    Ok(SeatbeltProfile { source })
}

pub(crate) fn build_policy_rules(config: &SandboxConfig) -> Result<String> {
    let mut source = String::from("(deny default)\n(debug deny)\n");

    for (index, rule) in config.fs.iter().enumerate() {
        let later_rules = &config.fs[index + 1..];
        match rule {
            FsAccess::ReadAllow(path) => {
                let exclusions = read_deny_paths(later_rules);
                push_path_rules(&mut source, "allow", &["file-read*"], path, &exclusions)?;
            }
            FsAccess::ReadDeny(path) => {
                let exclusions = read_allow_paths(later_rules);
                push_path_rules(&mut source, "deny", &["file-read*"], path, &exclusions)?;
            }
            FsAccess::WriteAllow(path) => {
                let exclusions = write_deny_paths(later_rules);
                push_path_rules(&mut source, "allow", &["file-write*"], path, &exclusions)?;
            }
            FsAccess::WriteDeny(path) => {
                let exclusions = write_allow_paths(later_rules);
                push_path_rules(&mut source, "deny", &["file-write*"], path, &exclusions)?;
            }
            FsAccess::ExecuteAllow(path) => {
                let exclusions = execute_deny_paths(later_rules);
                push_path_rules(
                    &mut source,
                    "allow",
                    &["file-map-executable", "process-exec*"],
                    path,
                    &exclusions,
                )?;
            }
            FsAccess::ExecuteDeny(path) => {
                let exclusions = execute_allow_paths(later_rules);
                push_path_rules(
                    &mut source,
                    "deny",
                    &["file-map-executable", "process-exec*"],
                    path,
                    &exclusions,
                )?;
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

    // `linux_ipc` is Linux-only and deliberately not consulted here: under
    // `(deny default)` IPC is already denied, and custom `.sb` profile imports
    // are the escape hatch for workloads that need more IPC.

    Ok(source)
}

fn push_path_rules(
    source: &mut String,
    action: &str,
    operations: &[&str],
    path: &Path,
    exclusions: &[PathBuf],
) -> Result<()> {
    for path in path_variants(path) {
        push_path_rule(source, action, operations, &path, exclusions)?;
    }
    Ok(())
}

fn push_path_rule(
    source: &mut String,
    action: &str,
    operations: &[&str],
    path: &Path,
    exclusions: &[PathBuf],
) -> Result<()> {
    for operation in operations {
        source.push_str(&format!("({action} {operation} "));
        push_subpath_filter(source, path, exclusions)?;
        source.push_str(")\n");
    }
    Ok(())
}

fn push_subpath_filter(source: &mut String, path: &Path, exclusions: &[PathBuf]) -> Result<()> {
    if exclusions.is_empty() {
        source.push_str("(subpath \"");
        source.push_str(&sbpl_string(path)?);
        source.push_str("\")");
        return Ok(());
    }

    source.push_str("(require-all (subpath \"");
    source.push_str(&sbpl_string(path)?);
    source.push_str("\")");
    for exclusion in exclusions {
        source.push_str(" (require-not (subpath \"");
        source.push_str(&sbpl_string(exclusion)?);
        source.push_str("\"))");
    }
    source.push(')');
    Ok(())
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

/// Convert a policy path to the body of an SBPL double-quoted string literal.
///
/// Fails closed on paths a quoted literal cannot carry faithfully — relative
/// paths, non-UTF-8 paths, and paths containing control characters — so
/// untrusted path strings cannot alter the structure of the generated profile.
pub(crate) fn sbpl_string(path: &Path) -> Result<String> {
    if !path.is_absolute() {
        return Err(invalid_path("sandbox policy path is not absolute", path));
    }
    let Some(text) = path.to_str() else {
        return Err(invalid_path("sandbox policy path is not valid UTF-8", path));
    };
    if text.chars().any(char::is_control) {
        return Err(invalid_path(
            "sandbox policy path contains a control character",
            path,
        ));
    }
    Ok(text.replace('\\', "\\\\").replace('"', "\\\""))
}

fn invalid_path(message: &str, path: &Path) -> Error {
    Error::confinement(
        "seatbelt-profile",
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{message}: {path:?}"),
        ),
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use guardrail_core::{
        IpcPolicy, NetworkPolicy, ResourceLimits, SandboxConfig, UserNamespacePolicy,
    };

    use super::*;

    fn empty_config() -> SandboxConfig {
        SandboxConfig {
            fs: vec![],
            network: NetworkPolicy::Deny,
            linux_ipc: IpcPolicy::Strict,
            limits: ResourceLimits::default(),
            env: BTreeMap::new(),
            darwin_sandbox_profiles: vec![],
            linux_user_namespaces: UserNamespacePolicy::Deny,
            windows_cache_namespace: None,
        }
    }

    #[test]
    fn default_config_denies_by_default() {
        let profile = build(&empty_config()).unwrap();

        assert_eq!(
            profile.source,
            "(version 1)\n(deny default)\n(debug deny)\n"
        );
    }

    #[test]
    fn imported_profiles_are_emitted_before_generated_rules() {
        let config = SandboxConfig {
            fs: vec![FsAccess::ReadAllow("/tmp/in".into())],
            network: NetworkPolicy::Deny,
            linux_ipc: IpcPolicy::Strict,
            limits: ResourceLimits::default(),
            env: BTreeMap::new(),
            darwin_sandbox_profiles: vec![],
            linux_user_namespaces: UserNamespacePolicy::Deny,
            windows_cache_namespace: None,
        };
        let profile = build_with_imports(
            &config,
            &[
                std::path::PathBuf::from("/tmp/base-one.sb"),
                std::path::PathBuf::from("/tmp/base-two.sb"),
            ],
        )
        .unwrap();

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
            &empty_config(),
            &[std::path::PathBuf::from(r#"/tmp/base"name\with-slash.sb"#)],
        )
        .unwrap();

        assert!(
            profile
                .source
                .contains(r#"(import "/tmp/base\"name\\with-slash.sb")"#)
        );
    }

    #[test]
    fn read_access_emits_file_read_subpath_rule() {
        let config = SandboxConfig {
            fs: vec![FsAccess::ReadAllow("/tmp/in".into())],
            network: NetworkPolicy::Deny,
            linux_ipc: IpcPolicy::Strict,
            limits: ResourceLimits::default(),
            env: BTreeMap::new(),
            darwin_sandbox_profiles: vec![],
            linux_user_namespaces: UserNamespacePolicy::Deny,
            windows_cache_namespace: None,
        };
        let profile = build(&config).unwrap();

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

        let config = SandboxConfig {
            fs: vec![FsAccess::ReadAllow(future_alias.clone())],
            network: NetworkPolicy::Deny,
            linux_ipc: IpcPolicy::Strict,
            limits: ResourceLimits::default(),
            env: BTreeMap::new(),
            darwin_sandbox_profiles: vec![],
            linux_user_namespaces: UserNamespacePolicy::Deny,
            windows_cache_namespace: None,
        };
        let profile = build(&config).unwrap();

        assert!(profile.source.contains(&format!(
            "(allow file-read* (subpath \"{}\"))\n",
            sbpl_string(&future_alias).unwrap()
        )));
        assert!(profile.source.contains(&format!(
            "(allow file-read* (subpath \"{}\"))\n",
            sbpl_string(&canonical_test_path(&future_real)).unwrap()
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

        let config = SandboxConfig {
            fs: vec![
                FsAccess::ReadAllow(alias.clone()),
                FsAccess::ReadDeny(secret_alias.clone()),
            ],
            network: NetworkPolicy::Deny,
            linux_ipc: IpcPolicy::Strict,
            limits: ResourceLimits::default(),
            env: BTreeMap::new(),
            darwin_sandbox_profiles: vec![],
            linux_user_namespaces: UserNamespacePolicy::Deny,
            windows_cache_namespace: None,
        };
        let profile = build(&config).unwrap();

        assert!(profile.source.contains(&format!(
            "(require-not (subpath \"{}\"))",
            sbpl_string(&secret_alias).unwrap()
        )));
        assert!(profile.source.contains(&format!(
            "(require-not (subpath \"{}\"))",
            sbpl_string(&canonical_test_path(&secret_real)).unwrap()
        )));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn read_deny_emits_file_read_deny_rule() {
        let config = SandboxConfig {
            fs: vec![FsAccess::ReadDeny("/tmp/secret".into())],
            network: NetworkPolicy::Deny,
            linux_ipc: IpcPolicy::Strict,
            limits: ResourceLimits::default(),
            env: BTreeMap::new(),
            darwin_sandbox_profiles: vec![],
            linux_user_namespaces: UserNamespacePolicy::Deny,
            windows_cache_namespace: None,
        };
        let profile = build(&config).unwrap();

        assert!(
            profile
                .source
                .contains("(deny file-read* (subpath \"/tmp/secret\"))\n")
        );
    }

    #[test]
    fn write_access_emits_only_file_write_subpath_rule() {
        let config = SandboxConfig {
            fs: vec![FsAccess::WriteAllow("/tmp/work".into())],
            network: NetworkPolicy::Deny,
            linux_ipc: IpcPolicy::Strict,
            limits: ResourceLimits::default(),
            env: BTreeMap::new(),
            darwin_sandbox_profiles: vec![],
            linux_user_namespaces: UserNamespacePolicy::Deny,
            windows_cache_namespace: None,
        };
        let profile = build(&config).unwrap();

        assert!(!profile.source.contains("(allow file-read*"));
        assert!(
            profile
                .source
                .contains("(allow file-write* (subpath \"/tmp/work\"))\n")
        );
    }

    #[test]
    fn write_deny_emits_only_file_write_deny_rule() {
        let config = SandboxConfig {
            fs: vec![FsAccess::WriteDeny("/tmp/work".into())],
            network: NetworkPolicy::Deny,
            linux_ipc: IpcPolicy::Strict,
            limits: ResourceLimits::default(),
            env: BTreeMap::new(),
            darwin_sandbox_profiles: vec![],
            linux_user_namespaces: UserNamespacePolicy::Deny,
            windows_cache_namespace: None,
        };
        let profile = build(&config).unwrap();

        assert!(!profile.source.contains("(deny file-read*"));
        assert!(
            profile
                .source
                .contains("(deny file-write* (subpath \"/tmp/work\"))\n")
        );
    }

    #[test]
    fn execute_access_emits_only_executable_rules() {
        let config = SandboxConfig {
            fs: vec![FsAccess::ExecuteAllow("/tmp/bin".into())],
            network: NetworkPolicy::Deny,
            linux_ipc: IpcPolicy::Strict,
            limits: ResourceLimits::default(),
            env: BTreeMap::new(),
            darwin_sandbox_profiles: vec![],
            linux_user_namespaces: UserNamespacePolicy::Deny,
            windows_cache_namespace: None,
        };
        let profile = build(&config).unwrap();

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
        let config = SandboxConfig {
            fs: vec![FsAccess::ExecuteDeny("/tmp/bin".into())],
            network: NetworkPolicy::Deny,
            linux_ipc: IpcPolicy::Strict,
            limits: ResourceLimits::default(),
            env: BTreeMap::new(),
            darwin_sandbox_profiles: vec![],
            linux_user_namespaces: UserNamespacePolicy::Deny,
            windows_cache_namespace: None,
        };
        let profile = build(&config).unwrap();

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
        let config = SandboxConfig {
            fs: vec![
                FsAccess::ReadAllow("/tmp".into()),
                FsAccess::ReadDeny("/tmp/secret".into()),
                FsAccess::ReadAllow("/tmp/secret/public.txt".into()),
                FsAccess::WriteAllow("/tmp/out".into()),
            ],
            network: NetworkPolicy::Deny,
            linux_ipc: IpcPolicy::Strict,
            limits: ResourceLimits::default(),
            env: BTreeMap::new(),
            darwin_sandbox_profiles: vec![],
            linux_user_namespaces: UserNamespacePolicy::Deny,
            windows_cache_namespace: None,
        };
        let profile = build(&config).unwrap();

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
        let config = empty_config();
        let profile = build(&config).unwrap();

        assert!(!profile.source.contains("network"));
    }

    #[test]
    fn outbound_network_emits_network_outbound_rule() {
        let config = SandboxConfig {
            fs: vec![],
            network: NetworkPolicy::OutboundOnly,
            linux_ipc: IpcPolicy::Strict,
            limits: ResourceLimits::default(),
            env: BTreeMap::new(),
            darwin_sandbox_profiles: vec![],
            linux_user_namespaces: UserNamespacePolicy::Deny,
            windows_cache_namespace: None,
        };
        let profile = build(&config).unwrap();

        assert!(profile.source.contains("(allow network-outbound)\n"));
        assert!(profile.source.contains("(allow system-socket)\n"));
    }

    #[test]
    fn full_network_emits_network_star_rule() {
        let config = SandboxConfig {
            fs: vec![],
            network: NetworkPolicy::Full,
            linux_ipc: IpcPolicy::Strict,
            limits: ResourceLimits::default(),
            env: BTreeMap::new(),
            darwin_sandbox_profiles: vec![],
            linux_user_namespaces: UserNamespacePolicy::Deny,
            windows_cache_namespace: None,
        };
        let profile = build(&config).unwrap();

        assert!(profile.source.contains("(allow network*)\n"));
        assert!(profile.source.contains("(allow system-socket)\n"));
    }

    #[test]
    fn double_quotes_in_paths_are_escaped() {
        let config = SandboxConfig {
            fs: vec![FsAccess::ReadAllow(r#"/tmp/name"with-quote"#.into())],
            network: NetworkPolicy::Deny,
            linux_ipc: IpcPolicy::Strict,
            limits: ResourceLimits::default(),
            env: BTreeMap::new(),
            darwin_sandbox_profiles: vec![],
            linux_user_namespaces: UserNamespacePolicy::Deny,
            windows_cache_namespace: None,
        };
        let profile = build(&config).unwrap();

        assert!(
            profile
                .source
                .contains(r#"(subpath "/tmp/name\"with-quote")"#)
        );
    }

    #[test]
    fn backslashes_in_paths_are_escaped() {
        let config = SandboxConfig {
            fs: vec![FsAccess::ReadAllow(r"/tmp/name\with-slash".into())],
            network: NetworkPolicy::Deny,
            linux_ipc: IpcPolicy::Strict,
            limits: ResourceLimits::default(),
            env: BTreeMap::new(),
            darwin_sandbox_profiles: vec![],
            linux_user_namespaces: UserNamespacePolicy::Deny,
            windows_cache_namespace: None,
        };
        let profile = build(&config).unwrap();

        assert!(
            profile
                .source
                .contains(r#"(subpath "/tmp/name\\with-slash")"#)
        );
    }

    #[test]
    fn control_characters_in_paths_are_rejected() {
        for path in [
            "/tmp/line\nfeed",
            "/tmp/carriage\rreturn",
            "/tmp/tab\there",
            "/tmp/nul\0byte",
        ] {
            let config = SandboxConfig {
                fs: vec![FsAccess::ReadAllow(path.into())],
                ..empty_config()
            };

            let result = build(&config);

            assert!(
                matches!(
                    result,
                    Err(Error::Confinement {
                        stage: "seatbelt-profile",
                        ..
                    })
                ),
                "expected rejection for {path:?}, got {result:?}"
            );
        }
    }

    #[test]
    fn control_characters_in_exclusion_paths_are_rejected() {
        let config = SandboxConfig {
            fs: vec![
                FsAccess::ReadAllow("/tmp".into()),
                FsAccess::ReadDeny("/tmp/eva\nsive".into()),
            ],
            ..empty_config()
        };

        assert!(matches!(
            build(&config),
            Err(Error::Confinement {
                stage: "seatbelt-profile",
                ..
            })
        ));
    }

    #[test]
    fn control_characters_in_import_paths_are_rejected() {
        let result = build_with_imports(
            &empty_config(),
            &[std::path::PathBuf::from("/tmp/base\nprofile.sb")],
        );

        assert!(matches!(
            result,
            Err(Error::Confinement {
                stage: "seatbelt-profile",
                ..
            })
        ));
    }

    #[test]
    fn relative_paths_are_rejected() {
        let config = SandboxConfig {
            fs: vec![FsAccess::ReadAllow("relative/never-exists".into())],
            ..empty_config()
        };

        assert!(matches!(
            build(&config),
            Err(Error::Confinement {
                stage: "seatbelt-profile",
                ..
            })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_paths_are_rejected() {
        use std::os::unix::ffi::OsStrExt;

        let config = SandboxConfig {
            fs: vec![FsAccess::ReadAllow(
                std::ffi::OsStr::from_bytes(b"/tmp/\xff\xfe").into(),
            )],
            ..empty_config()
        };

        assert!(matches!(
            build(&config),
            Err(Error::Confinement {
                stage: "seatbelt-profile",
                ..
            })
        ));
    }

    #[test]
    fn leading_dash_paths_are_embedded_literally() {
        let config = SandboxConfig {
            fs: vec![FsAccess::ReadAllow("/tmp/-rf".into())],
            ..empty_config()
        };
        let profile = build(&config).unwrap();

        assert!(profile.source.contains("(subpath \"/tmp/-rf\")"));
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
