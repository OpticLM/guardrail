//! Maps a Windows sandboxed child's exit status to a best-effort violation.
//!
//! Windows does not expose an AppContainer filesystem or network denial to the
//! parent as a precise signal. These explanations therefore stay heuristic and
//! name likely builder calls without claiming exact attribution.

use std::process::ExitStatus;

use guardrail_core::{NetworkPolicy, SandboxConfig, Violation, ViolationKind};

/// Explain why `status` likely indicates a policy violation, given the `config`
/// the child ran under. Returns `None` if the child exited successfully.
pub fn explain(config: &SandboxConfig, status: ExitStatus) -> Option<Violation> {
    if status.success() {
        return None;
    }

    if let Some(violation) = resource_violation(config, status) {
        return Some(violation);
    }

    Some(policy_violation(config, status))
}

fn resource_violation(config: &SandboxConfig, status: ExitStatus) -> Option<Violation> {
    let mut suggestions = Vec::new();

    if config.limits.memory_bytes.is_some() {
        suggestions.push("raise the active memory cap: .memory_limit_mb(<larger>)".to_string());
    }
    if config.limits.cpu_time_secs.is_some() {
        suggestions.push("raise the active CPU cap: .cpu_time_limit_secs(<larger>)".to_string());
    }
    if config.limits.max_processes.is_some() {
        suggestions.push("raise the active process cap: .max_processes(<larger>)".to_string());
    }

    if suggestions.is_empty() {
        return None;
    }

    Some(Violation {
        kind: ViolationKind::ResourceLimit,
        summary: format!(
            "process exited unsuccessfully ({status}); it likely hit an active Windows Job Object resource limit"
        ),
        suggestions,
    })
}

fn policy_violation(config: &SandboxConfig, status: ExitStatus) -> Violation {
    let mut suggestions = vec![
        "if it likely needs file reads, grant them: .allow_read(\"<path>\")".to_string(),
        "if it may write files, grant the output directory: .allow_write(\"<path>\")".to_string(),
    ];

    match config.network {
        NetworkPolicy::Deny => suggestions.push(
            "if it may need outbound network, relax it: .network(NetworkPolicy::OutboundOnly)"
                .to_string(),
        ),
        NetworkPolicy::OutboundOnly => suggestions.push(
            "if it may bind or listen on sockets, use: .network(NetworkPolicy::Full)".to_string(),
        ),
        NetworkPolicy::Full => {}
    }

    let kind = if config.network == NetworkPolicy::Full {
        ViolationKind::Filesystem
    } else {
        ViolationKind::Unknown
    };

    Violation {
        kind,
        summary: format!(
            "process exited unsuccessfully ({status}); Windows AppContainer policy likely denied filesystem or network access"
        ),
        suggestions,
    }
}
