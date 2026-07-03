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
    let mut source = String::from("(deny default)\n");

    for rule in &config.fs {
        match rule {
            FsAccess::ReadAllow(path) => {
                let path = sbpl_string(path);
                source.push_str(&format!("(allow file-read* (subpath \"{path}\"))\n"));
            }
            FsAccess::ReadDeny(path) => {
                let path = sbpl_string(path);
                source.push_str(&format!("(deny file-read* (subpath \"{path}\"))\n"));
            }
            FsAccess::WriteAllow(path) => {
                let path = sbpl_string(path);
                source.push_str(&format!("(allow file-write* (subpath \"{path}\"))\n"));
            }
            FsAccess::WriteDeny(path) => {
                let path = sbpl_string(path);
                source.push_str(&format!("(deny file-write* (subpath \"{path}\"))\n"));
            }
            FsAccess::ExecuteAllow(path) => {
                let path = sbpl_string(path);
                source.push_str(&format!(
                    "(allow file-map-executable (subpath \"{path}\"))\n"
                ));
                source.push_str(&format!("(allow process-exec* (subpath \"{path}\"))\n"));
            }
            FsAccess::ExecuteDeny(path) => {
                let path = sbpl_string(path);
                source.push_str(&format!(
                    "(deny file-map-executable (subpath \"{path}\"))\n"
                ));
                source.push_str(&format!("(deny process-exec* (subpath \"{path}\"))\n"));
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

pub(crate) fn sbpl_string(path: &std::path::Path) -> String {
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

        assert_eq!(profile.source, "(version 1)\n(deny default)\n");
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

        assert_eq!(
            profile.source,
            format!(
                "(version 1)\n\
                 (import \"/tmp/base-one.sb\")\n\
                 (import \"/tmp/base-two.sb\")\n\
                 (deny default)\n\
                 (allow file-read* (subpath \"/tmp/in\"))\n"
            )
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

        assert_eq!(
            profile.source,
            "(version 1)\n\
             (deny default)\n\
             (allow file-read* (subpath \"/tmp\"))\n\
             (deny file-read* (subpath \"/tmp/secret\"))\n\
             (allow file-read* (subpath \"/tmp/secret/public.txt\"))\n\
             (allow file-write* (subpath \"/tmp/out\"))\n"
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
}
