//! Windows override of [`Backend::explain`](guardrail_core::Backend::explain).
//!
//! Windows does not expose an AppContainer filesystem or network denial to the
//! parent as a precise signal. These explanations therefore stay heuristic and
//! name likely builder calls without claiming exact attribution.
//!
//! The shared success-check lives in `guardrail_core::diagnostics`; this module
//! adds the Windows-specific resource-limit and policy fallbacks. Windows Job
//! Object kills are not surfaced to the parent as a Unix-style signal, so
//! resource attribution here is driven by which caps the `config` actually set
//! rather than by an exit signal.

use std::process::ExitStatus;

use guardrail_core::{ExplainCtx, NetworkPolicy, SandboxConfig, Violation, ViolationKind};

/// The Windows [`Backend::explain`](guardrail_core::Backend::explain) override.
pub(crate) fn explain(ctx: &ExplainCtx<'_>) -> Option<Violation> {
    if ctx.status.success() {
        return None;
    }

    if let Some(violation) = resource_violation(ctx.config, ctx.status) {
        return Some(violation);
    }

    Some(policy_violation(ctx.config, ctx.status))
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
        "if it likely needs file reads, grant them: \
         FsAccess::ReadAllow(\"<path>\")"
            .to_string(),
        "if it may write files, grant the output directory: \
         FsAccess::WriteAllow(\"<path>\")"
            .to_string(),
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
