//! macOS override of [`Backend::explain`](guardrail_core::Backend::explain).
//!
//! Seatbelt does not give the parent a synchronous violation notification.
//! Generated profiles enable `(debug deny)`, which can produce sandbox denial
//! lines in stderr or the macOS unified log. When a caller captures that text
//! and passes it via [`ExplainCtx::captured`], these helpers classify the
//! denial lines; otherwise the override falls back to exit-status heuristics.
//!
//! The shared success-check and resource-signal logic lives in
//! `guardrail_core::diagnostics`; this module adds only the Seatbelt-specific
//! denial-line parsing and the macOS-flavoured fallback. The explanation is
//! pure text/exit-status logic, so the override is not `cfg`-gated and the
//! Seatbelt parsing stays unit-testable on Linux.

use std::process::ExitStatus;

use guardrail_core::{ExplainCtx, NetworkPolicy, SandboxConfig, Violation, ViolationKind};

/// The macOS [`Backend::explain`](guardrail_core::Backend::explain) override.
///
/// Uses `ctx.captured` (if present) to parse Seatbelt `(debug deny)` lines for
/// specific suggestions, then falls back to a resource-signal check and a
/// conservative filesystem/Seatbelt fallback.
pub(crate) fn explain(ctx: &ExplainCtx<'_>) -> Option<Violation> {
    if ctx.status.success() {
        return None;
    }

    if let Some(text) = ctx.captured
        && let Some(violation) = explain_seatbelt_denial(ctx.config, ctx.status, text)
    {
        return Some(violation);
    }

    #[cfg(unix)]
    if let Some(violation) =
        guardrail_core::diagnostics::resource_signal_violation(ctx.config, ctx.status)
    {
        return Some(violation);
    }

    if let Some(text) = ctx.captured
        && let Some(violation) = explain_permission_text(ctx.status, text)
    {
        return Some(violation);
    }

    Some(Violation {
        kind: ViolationKind::Filesystem,
        summary: format!(
            "process exited unsuccessfully ({}); on macOS this is often a Seatbelt denial",
            ctx.status
        ),
        suggestions: vec![
            "grant read access: .fs([FsAccess::ReadAllow(\"<path>\".into())])".to_string(),
            "grant write access: .fs([FsAccess::WriteAllow(\"<path>\".into())])".to_string(),
            "for macOS-specific operations, import a Seatbelt profile: \
             .darwin_sandbox_profiles([\"<profile.sb>\".into()])"
                .to_string(),
        ],
    })
}

fn explain_seatbelt_denial(
    config: &SandboxConfig,
    status: ExitStatus,
    diagnostics: &str,
) -> Option<Violation> {
    let denial = find_denial(diagnostics)?;
    let suggestions = suggestions_for_denial(config, denial.operation, denial.subject);

    Some(Violation {
        kind: kind_for_operation(denial.operation),
        summary: format!(
            "process exited unsuccessfully ({status}); Seatbelt denied {}{}",
            denial.operation,
            denial
                .subject
                .map(|subject| format!(" for {subject}"))
                .unwrap_or_default()
        ),
        suggestions,
    })
}

fn explain_permission_text(status: ExitStatus, diagnostics: &str) -> Option<Violation> {
    let path = find_permission_denied_path(diagnostics)?;

    Some(Violation {
        kind: ViolationKind::Filesystem,
        summary: format!(
            "process exited unsuccessfully ({status}); captured output reported Permission denied \
             for {path}"
        ),
        suggestions: vec![
            format!(
                "grant read access: .fs([FsAccess::ReadAllow(\"{}\".into())])",
                escape_builder_string(path)
            ),
            format!(
                "grant write access: .fs([FsAccess::WriteAllow(\"{}\".into())])",
                escape_builder_string(path)
            ),
        ],
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Denial<'a> {
    operation: &'a str,
    subject: Option<&'a str>,
}

fn find_denial(diagnostics: &str) -> Option<Denial<'_>> {
    diagnostics.lines().filter_map(parse_denial_line).next()
}

fn parse_denial_line(line: &str) -> Option<Denial<'_>> {
    let after_deny = line.split_once(" deny(")?.1;
    let after_code = after_deny.split_once(')')?.1.trim_start();
    let (operation, subject) = after_code.split_once(char::is_whitespace).map_or(
        (after_code, None),
        |(operation, subject)| {
            let subject = subject.trim();
            (
                operation,
                if subject.is_empty() {
                    None
                } else {
                    Some(subject)
                },
            )
        },
    );
    if operation.is_empty() {
        return None;
    }

    Some(Denial { operation, subject })
}

fn suggestions_for_denial(
    config: &SandboxConfig,
    operation: &str,
    subject: Option<&str>,
) -> Vec<String> {
    if operation.starts_with("file-read") {
        return vec![format!(
            "grant read access: .fs([FsAccess::ReadAllow(\"{}\".into())])",
            builder_arg(subject, "<path>")
        )];
    }

    if operation.starts_with("file-write") {
        return vec![format!(
            "grant write access: .fs([FsAccess::WriteAllow(\"{}\".into())])",
            builder_arg(subject, "<path>")
        )];
    }

    if operation == "file-map-executable" || operation.starts_with("process-exec") {
        return vec![format!(
            "grant execute access: .fs([FsAccess::ExecuteAllow(\"{}\".into())])",
            builder_arg(subject, "<path>")
        )];
    }

    if operation.starts_with("network") {
        return match config.network {
            NetworkPolicy::Deny => {
                vec![
                    "allow outbound networking: .network(NetworkPolicy::OutboundOnly)".to_string(),
                    "or allow outbound plus bind/listen: .network(NetworkPolicy::Full)".to_string(),
                ]
            }
            NetworkPolicy::OutboundOnly => {
                vec!["allow bind/listen networking: .network(NetworkPolicy::Full)".to_string()]
            }
            NetworkPolicy::Full => {
                vec![
                    "network is already fully allowed; inspect the Seatbelt operation and any \
                     imported profile"
                        .to_string(),
                ]
            }
        };
    }

    vec![format!(
        "allow the macOS-specific Seatbelt operation with an imported profile: \
         .darwin_sandbox_profiles([\"<profile.sb>\".into()]) for operation {operation}"
    )]
}

fn kind_for_operation(operation: &str) -> ViolationKind {
    if operation.starts_with("file-") || operation.starts_with("process-exec") {
        ViolationKind::Filesystem
    } else {
        ViolationKind::Unknown
    }
}

fn find_permission_denied_path(diagnostics: &str) -> Option<&str> {
    diagnostics
        .lines()
        .find_map(|line| path_before_suffix(line, ": Permission denied"))
        .or_else(|| {
            diagnostics
                .lines()
                .find_map(|line| path_before_suffix(line, ": Operation not permitted"))
        })
}

fn path_before_suffix<'a>(line: &'a str, suffix: &str) -> Option<&'a str> {
    let before = line.split_once(suffix)?.0.trim();
    let candidate = before.rsplit_once(": ").map_or(before, |(_, path)| path);
    if candidate.starts_with('/') {
        Some(candidate)
    } else {
        None
    }
}

fn builder_arg(value: Option<&str>, placeholder: &str) -> String {
    value
        .map(escape_builder_string)
        .unwrap_or_else(|| placeholder.to_string())
}

fn escape_builder_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    #[cfg(unix)]
    use std::os::unix::process::ExitStatusExt;
    #[cfg(windows)]
    use std::os::windows::process::ExitStatusExt;

    use guardrail_core::{ExplainCtx, IpcPolicy, NetworkPolicy, ResourceLimits, SandboxConfig, ViolationKind};

    use super::*;

    fn empty_config() -> SandboxConfig {
        SandboxConfig {
            fs: vec![],
            network: NetworkPolicy::Deny,
            ipc: IpcPolicy::Strict,
            limits: ResourceLimits::default(),
            env: BTreeMap::new(),
            darwin_sandbox_profiles: vec![],
        }
    }

    fn exit_status(code: i32) -> ExitStatus {
        #[cfg(unix)]
        {
            ExitStatus::from_raw(code << 8)
        }
        #[cfg(windows)]
        {
            ExitStatus::from_raw(code as u32)
        }
    }

    #[cfg(unix)]
    fn signaled_status(signal: i32) -> ExitStatus {
        ExitStatus::from_raw(signal)
    }

    fn explain(config: &guardrail_core::SandboxConfig, status: ExitStatus) -> Option<Violation> {
        super::explain(&ExplainCtx::new(config, status))
    }

    fn explain_with_text(
        config: &guardrail_core::SandboxConfig,
        status: ExitStatus,
        text: &str,
    ) -> Option<Violation> {
        super::explain(&ExplainCtx::new(config, status).with_captured(text))
    }

    #[test]
    fn success_yields_no_violation() {
        let config = empty_config();

        assert!(explain(&config, exit_status(0)).is_none());
    }

    #[test]
    fn seatbelt_file_read_denial_suggests_read_grant() {
        let config = empty_config();
        let text = "Sandbox: cat(123) deny(1) file-read-data /private/tmp/input.txt";

        let violation = explain_with_text(&config, exit_status(1), text).expect("violation");

        assert_eq!(violation.kind, ViolationKind::Filesystem);
        assert!(violation.summary.contains("file-read-data"));
        assert_eq!(
            violation.suggestions,
            vec![
                "grant read access: \
                 .fs([FsAccess::ReadAllow(\"/private/tmp/input.txt\".into())])"
            ]
        );
    }

    #[test]
    fn seatbelt_write_denial_suggests_write_grant() {
        let config = empty_config();
        let text = "Sandbox: touch(123) deny(1) file-write-create /private/tmp/out.txt";

        let violation = explain_with_text(&config, exit_status(1), text).expect("violation");

        assert_eq!(
            violation.suggestions,
            vec![
                "grant write access: \
                 .fs([FsAccess::WriteAllow(\"/private/tmp/out.txt\".into())])"
            ]
        );
    }

    #[test]
    fn seatbelt_network_denial_suggests_network_policy() {
        let config = SandboxConfig {
            fs: vec![],
            network: NetworkPolicy::Deny,
            ipc: IpcPolicy::Strict,
            limits: ResourceLimits::default(),
            env: BTreeMap::new(),
            darwin_sandbox_profiles: vec![],
        };
        let text = "Sandbox: curl(123) deny(1) network-outbound 93.184.216.34:443";

        let violation = explain_with_text(&config, exit_status(1), text).expect("violation");

        assert_eq!(violation.kind, ViolationKind::Unknown);
        assert!(
            violation
                .suggestions
                .iter()
                .any(|s| s.contains("NetworkPolicy::OutboundOnly"))
        );
    }

    #[test]
    fn generic_permission_denied_output_suggests_filesystem_grants() {
        let config = empty_config();
        let text = "cat: /Users/me/secret.txt: Permission denied";

        let violation = explain_with_text(&config, exit_status(1), text).expect("violation");

        assert_eq!(violation.kind, ViolationKind::Filesystem);
        assert!(
            violation.suggestions.contains(
                &"grant read access: \
                    .fs([FsAccess::ReadAllow(\"/Users/me/secret.txt\".into())])"
                    .to_string()
            )
        );
    }

    #[cfg(unix)]
    #[test]
    fn cpu_signal_is_diagnosed_as_resource_limit_when_configured() {
        let config = SandboxConfig {
            fs: vec![],
            network: NetworkPolicy::Deny,
            ipc: IpcPolicy::Strict,
            limits: ResourceLimits { memory_bytes: None, cpu_time_secs: Some(1), max_processes: None },
            env: BTreeMap::new(),
            darwin_sandbox_profiles: vec![],
        };

        let violation =
            explain(&config, signaled_status(libc::SIGXCPU)).expect("resource violation");

        assert_eq!(violation.kind, ViolationKind::ResourceLimit);
        assert!(
            violation
                .suggestions
                .contains(&"raise the CPU cap: .cpu_time_limit_secs(<larger>)".to_string())
        );
    }

    #[test]
    fn fallback_mentions_seatbelt_profile_escape_hatch() {
        let config = empty_config();

        let violation = explain(&config, exit_status(1)).expect("fallback violation");

        assert_eq!(violation.kind, ViolationKind::Filesystem);
        assert!(
            violation
                .suggestions
                .iter()
                .any(|s| s.contains("darwin_sandbox_profile"))
        );
    }
}
