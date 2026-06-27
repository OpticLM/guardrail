//! Linux override of [`Backend::explain`](guardrail_core::Backend::explain).
//!
//! See the module-level note in `guardrail_core::diagnostics`: this is
//! heuristic. seccomp violations are observable (SIGSYS); Landlock denials are
//! NOT visible to the parent, so filesystem attribution is a fallback guess.
//!
//! The shared success-check and resource-signal logic lives in
//! `guardrail_core::diagnostics`; this module adds only the Linux-specific
//! attribution (SIGSYS → seccomp, capped-memory guess, filesystem fallback).

use guardrail_core::diagnostics::resource_signal_violation;
use guardrail_core::{
    ExplainCtx, IpcPolicy, NetworkPolicy, SandboxConfig, Violation, ViolationKind,
};

/// The Linux [`Backend::explain`](guardrail_core::Backend::explain) override.
pub(crate) fn explain(ctx: &ExplainCtx<'_>) -> Option<Violation> {
    use std::os::unix::process::ExitStatusExt;

    if ctx.status.success() {
        return None;
    }

    if let Some(sig) = ctx.status.signal() {
        if sig == libc::SIGSYS {
            return Some(seccomp_violation(ctx.config));
        }
        if (sig == libc::SIGXCPU || sig == libc::SIGKILL)
            && let Some(violation) = resource_signal_violation(ctx.config, ctx.status)
        {
            return Some(violation);
        }
    }

    // Non-success with no attributable signal. If memory was capped, a failed
    // allocation is plausible; otherwise the most common silent denial is the
    // filesystem (Landlock gives the parent no signal).
    if ctx.config.limits.memory_bytes.is_some() {
        return Some(Violation {
            kind: ViolationKind::ResourceLimit,
            summary: format!(
                "process exited unsuccessfully ({}); it may have hit the memory limit",
                ctx.status
            ),
            suggestions: vec![
                "raise or remove the memory cap: .memory_limit_mb(<larger>)".to_string(),
            ],
        });
    }

    Some(Violation {
        kind: ViolationKind::Filesystem,
        summary: format!(
            "process exited unsuccessfully ({}); if it reported \
             'Permission denied' on a file, a filesystem grant is likely missing",
            ctx.status
        ),
        suggestions: vec![
            "grant read access: .allow_read(\"<path>\")".to_string(),
            "grant write access: .allow_write(\"<path>\")".to_string(),
        ],
    })
}

fn seccomp_violation(config: &SandboxConfig) -> Violation {
    let mut suggestions = Vec::new();
    // Only suggest loosening policies that are currently restrictive.
    if config.network != NetworkPolicy::Full {
        suggestions.push(
            "if it needs network: .network(NetworkPolicy::OutboundOnly) (or ::Full to bind/listen)"
                .to_string(),
        );
    }
    if config.ipc != IpcPolicy::Relaxed {
        suggestions.push(
            "if it needs shared memory / message queues: .ipc(IpcPolicy::Relaxed)".to_string(),
        );
    }
    if suggestions.is_empty() {
        // Network is Full and IPC is Relaxed already: the only thing still
        // blocked is process inspection (ptrace/process_vm_*), which is never
        // unblockable by design.
        suggestions.push(
            "the blocked call was process inspection (ptrace/process_vm_*), which the \
             sandbox never permits; the program cannot run under guardrail"
                .to_string(),
        );
    }
    Violation {
        kind: ViolationKind::Seccomp,
        summary: "process was killed by SIGSYS - a syscall blocked by the seccomp filter \
                  (network or IPC)"
            .to_string(),
        suggestions,
    }
}
