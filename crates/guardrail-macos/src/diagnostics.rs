//! Best-effort diagnostics for macOS Seatbelt denials.
//!
//! Seatbelt does not give the parent a synchronous violation notification.
//! Generated profiles enable `(debug deny)`, which can produce sandbox denial
//! lines in stderr or the macOS unified log. These helpers classify those lines
//! when callers capture them, and otherwise fall back to exit-status heuristics.

use std::process::{ExitStatus, Output};

use guardrail_core::{NetworkPolicy, SandboxConfig, Violation, ViolationKind};

/// Explain why `status` likely indicates a macOS sandbox policy violation.
///
/// This mirrors `guardrail_linux::diagnostics::explain`: it returns `None` for
/// success, reports resource-limit signals when visible, and otherwise returns a
/// conservative filesystem/Seatbelt fallback.
pub fn explain(config: &SandboxConfig, status: ExitStatus) -> Option<Violation> {
    explain_impl(config, status, None)
}

/// Explain a failed run using both exit status and captured stdout/stderr.
///
/// Use this when the command was spawned with piped stdio and consumed through
/// `wait_with_output()`. Captured Seatbelt `(debug deny)` lines allow more
/// specific suggestions than exit status alone.
pub fn explain_with_output(config: &SandboxConfig, output: &Output) -> Option<Violation> {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = if stdout.is_empty() {
        stderr.into_owned()
    } else if stderr.is_empty() {
        stdout.into_owned()
    } else {
        format!("{stderr}\n{stdout}")
    };

    explain_impl(config, output.status, Some(combined.as_str()))
}

/// Explain a failed run using exit status and captured diagnostic text.
///
/// `diagnostics` can be the child's stderr, merged stdout/stderr, or relevant
/// `log stream` / `log show` output containing Seatbelt denial lines.
pub fn explain_with_diagnostics(
    config: &SandboxConfig,
    status: ExitStatus,
    diagnostics: &str,
) -> Option<Violation> {
    explain_impl(config, status, Some(diagnostics))
}

fn explain_impl(
    config: &SandboxConfig,
    status: ExitStatus,
    diagnostics: Option<&str>,
) -> Option<Violation> {
    if status.success() {
        return None;
    }

    if let Some(text) = diagnostics
        && let Some(violation) = explain_seatbelt_denial(config, status, text)
    {
        return Some(violation);
    }

    if let Some(violation) = resource_violation(config, status) {
        return Some(violation);
    }

    if let Some(text) = diagnostics
        && let Some(violation) = explain_permission_text(status, text)
    {
        return Some(violation);
    }

    Some(Violation {
        kind: ViolationKind::Filesystem,
        summary: format!(
            "process exited unsuccessfully ({status}); on macOS this is often a Seatbelt denial"
        ),
        suggestions: vec![
            "grant read access: .allow_read(\"<path>\")".to_string(),
            "grant write access: .allow_write(\"<path>\")".to_string(),
            "for macOS-specific operations, import a Seatbelt profile: \
             .darwin_sandbox_profile(\"<profile.sb>\")"
                .to_string(),
        ],
    })
}

fn resource_violation(config: &SandboxConfig, status: ExitStatus) -> Option<Violation> {
    use std::os::unix::process::ExitStatusExt;

    let signal = status.signal()?;
    if signal != libc::SIGXCPU && signal != libc::SIGKILL {
        return None;
    }

    let mut suggestions = Vec::new();
    if config.limits.cpu_time_secs.is_some() {
        suggestions.push("raise the CPU cap: .cpu_time_limit_secs(<larger>)".to_string());
    }
    if config.limits.memory_bytes.is_some() {
        suggestions.push("raise the memory cap: .memory_limit_mb(<larger>)".to_string());
    }
    if suggestions.is_empty() {
        return None;
    }

    Some(Violation {
        kind: ViolationKind::ResourceLimit,
        summary: "process was killed by a resource limit (CPU time or memory)".to_string(),
        suggestions,
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
                "grant read access: .allow_read(\"{}\")",
                escape_builder_string(path)
            ),
            format!(
                "grant write access: .allow_write(\"{}\")",
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
    if operation.starts_with("file-read") || operation == "file-map-executable" {
        return vec![format!(
            "grant read access: .allow_read(\"{}\")",
            builder_arg(subject, "<path>")
        )];
    }

    if operation.starts_with("file-write") {
        return vec![format!(
            "grant write access: .allow_write(\"{}\")",
            builder_arg(subject, "<path>")
        )];
    }

    if operation.starts_with("process-exec") {
        return vec![format!(
            "grant execute access: .allow_execute(\"{}\")",
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
         .darwin_sandbox_profile(\"<profile.sb>\") for operation {operation}"
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
    use std::os::unix::process::ExitStatusExt;

    use guardrail_core::{NetworkPolicy, SandboxBuilder, ViolationKind};

    use super::*;

    fn exit_status(code: i32) -> ExitStatus {
        ExitStatus::from_raw(code << 8)
    }

    fn signaled_status(signal: i32) -> ExitStatus {
        ExitStatus::from_raw(signal)
    }

    #[test]
    fn success_yields_no_violation() {
        let config = SandboxBuilder::new().build();

        assert!(explain(&config, exit_status(0)).is_none());
    }

    #[test]
    fn seatbelt_file_read_denial_suggests_read_grant() {
        let config = SandboxBuilder::new().build();
        let text = "Sandbox: cat(123) deny(1) file-read-data /private/tmp/input.txt";

        let violation = explain_with_diagnostics(&config, exit_status(1), text).expect("violation");

        assert_eq!(violation.kind, ViolationKind::Filesystem);
        assert!(violation.summary.contains("file-read-data"));
        assert_eq!(
            violation.suggestions,
            vec!["grant read access: .allow_read(\"/private/tmp/input.txt\")"]
        );
    }

    #[test]
    fn seatbelt_write_denial_suggests_write_grant() {
        let config = SandboxBuilder::new().build();
        let text = "Sandbox: touch(123) deny(1) file-write-create /private/tmp/out.txt";

        let violation = explain_with_diagnostics(&config, exit_status(1), text).expect("violation");

        assert_eq!(
            violation.suggestions,
            vec!["grant write access: .allow_write(\"/private/tmp/out.txt\")"]
        );
    }

    #[test]
    fn seatbelt_network_denial_suggests_network_policy() {
        let config = SandboxBuilder::new().network(NetworkPolicy::Deny).build();
        let text = "Sandbox: curl(123) deny(1) network-outbound 93.184.216.34:443";

        let violation = explain_with_diagnostics(&config, exit_status(1), text).expect("violation");

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
        let config = SandboxBuilder::new().build();
        let text = "cat: /Users/me/secret.txt: Permission denied";

        let violation = explain_with_diagnostics(&config, exit_status(1), text).expect("violation");

        assert_eq!(violation.kind, ViolationKind::Filesystem);
        assert!(
            violation
                .suggestions
                .contains(&"grant read access: .allow_read(\"/Users/me/secret.txt\")".to_string())
        );
    }

    #[test]
    fn cpu_signal_is_diagnosed_as_resource_limit_when_configured() {
        let config = SandboxBuilder::new().cpu_time_limit_secs(1).build();

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
        let config = SandboxBuilder::new().build();

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
