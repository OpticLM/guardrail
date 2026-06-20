//! Maps a sandboxed child's exit status to a best-effort [`Violation`].
//!
//! See the module-level note in `guardrail_core::diagnostics`: this is
//! heuristic. seccomp violations are observable (SIGSYS); Landlock denials are
//! NOT visible to the parent, so filesystem attribution is a fallback guess.

use std::process::ExitStatus;

use guardrail_core::{IpcPolicy, NetworkPolicy, SandboxConfig, Violation, ViolationKind};

/// Explain why `status` likely indicates a policy violation, given the `config`
/// the child ran under. Returns `None` if the child exited successfully.
pub fn explain(config: &SandboxConfig, status: ExitStatus) -> Option<Violation> {
    use std::os::unix::process::ExitStatusExt;

    if status.success() {
        return None;
    }

    if let Some(sig) = status.signal() {
        if sig == libc::SIGSYS {
            return Some(seccomp_violation(config));
        }
        if (sig == libc::SIGXCPU || sig == libc::SIGKILL)
            && let Some(v) = resource_violation(config)
        {
            return Some(v);
        }
    }

    // Non-success with no attributable signal. If memory was capped, a failed
    // allocation is plausible; otherwise the most common silent denial is the
    // filesystem (Landlock gives the parent no signal).
    if config.limits.memory_bytes.is_some() {
        return Some(Violation {
            kind: ViolationKind::ResourceLimit,
            summary: format!(
                "process exited unsuccessfully ({status}); it may have hit the memory limit"
            ),
            suggestions: vec![
                "raise or remove the memory cap: .memory_limit_mb(<larger>)".to_string(),
            ],
        });
    }

    Some(Violation {
        kind: ViolationKind::Filesystem,
        summary: format!(
            "process exited unsuccessfully ({status}); if it reported \
             'Permission denied' on a file, a filesystem grant is likely missing"
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

fn resource_violation(config: &SandboxConfig) -> Option<Violation> {
    let mut suggestions = Vec::new();
    if config.limits.cpu_time_secs.is_some() {
        suggestions.push("raise the CPU cap: .cpu_time_limit_secs(<larger>)".to_string());
    }
    if config.limits.memory_bytes.is_some() {
        suggestions.push("raise the memory cap: .memory_limit_mb(<larger>)".to_string());
    }
    if suggestions.is_empty() {
        return None; // killed by a signal but no resource limit was set
    }
    Some(Violation {
        kind: ViolationKind::ResourceLimit,
        summary: "process was killed by a resource limit (CPU time or memory)".to_string(),
        suggestions,
    })
}
