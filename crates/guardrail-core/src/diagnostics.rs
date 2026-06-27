//! Best-effort observability for policy violations.
//!
//! These types describe *why a sandboxed process likely failed* and *which
//! policy to add*. They are heuristic: the parent process cannot observe the
//! exact syscall or path a backend denied, so a [`Violation`] narrows the
//! cause from the exit status and the active configuration rather than
//! pinpointing it.
//!
//! Backends produce these via [`crate::Backend::explain`], which receives an
//! [`ExplainCtx`]. [`portable_explain`] is the default implementation used when
//! a backend does not override it, and [`resource_signal_violation`] is the
//! shared Unix resource-limit heuristic that the Linux and macOS backends
//! compose into their own overrides — so the common "success check" and
//! "killed by a resource signal" logic lives in one place instead of three.

use std::fmt;
use std::process::ExitStatus;

use crate::config::SandboxConfig;

/// The category of a suspected policy violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ViolationKind {
    /// A syscall blocked by the seccomp filter (network or IPC).
    Seccomp,
    /// A resource limit (memory / CPU time / process count) was hit.
    ResourceLimit,
    /// Likely a filesystem denial (no parent-visible signal; inferred).
    Filesystem,
    /// Could not be attributed to a specific policy.
    Unknown,
}

/// An actionable explanation of a suspected policy violation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    /// The suspected category.
    pub kind: ViolationKind,
    /// One-line human summary of what was observed.
    pub summary: String,
    /// Concrete, copy-pasteable next steps (builder calls to add a policy).
    pub suggestions: Vec<String>,
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.summary)?;
        for s in &self.suggestions {
            write!(f, "\n  - {s}")?;
        }
        Ok(())
    }
}

/// What a [`Backend`](crate::Backend) receives when explaining a failed run.
///
/// `config` is the policy the child ran under and `status` is its exit status.
/// `captured` is any stdout/stderr text the caller collected (e.g. a macOS
/// Seatbelt `(debug deny)` line), which lets a backend produce more specific
/// suggestions than the exit status alone; it is `None` when stdio was
/// inherited and nothing was captured.
pub struct ExplainCtx<'a> {
    /// The policy the child ran under.
    pub config: &'a SandboxConfig,
    /// The child's exit status.
    pub status: ExitStatus,
    /// Captured child output (stderr / merged stdio), if the caller piped it.
    pub captured: Option<&'a str>,
}

impl<'a> ExplainCtx<'a> {
    /// Explain a run from just its exit status (no captured output).
    pub fn new(config: &'a SandboxConfig, status: ExitStatus) -> Self {
        Self {
            config,
            status,
            captured: None,
        }
    }

    /// Attach captured child output so the backend can parse denial lines.
    pub fn with_captured(mut self, captured: &'a str) -> Self {
        self.captured = Some(captured);
        self
    }
}

/// The default [`Backend::explain`](crate::Backend::explain): a
/// platform-agnostic heuristic used when a backend does not override it.
///
/// Returns `None` on success, reports a resource-limit signal on Unix, and
/// otherwise falls back to a generic filesystem suggestion. Platform backends
/// override [`Backend::explain`](crate::Backend::explain) to add their own
/// signal/Seatbelt attribution.
pub(crate) fn portable_explain(ctx: &ExplainCtx<'_>) -> Option<Violation> {
    if ctx.status.success() {
        return None;
    }

    #[cfg(unix)]
    if let Some(violation) = resource_signal_violation(ctx.config, ctx.status) {
        return Some(violation);
    }

    Some(Violation {
        kind: ViolationKind::Filesystem,
        summary: format!("process exited unsuccessfully ({})", ctx.status),
        suggestions: vec![
            "grant read access: .allow_read(\"<path>\")".to_string(),
            "grant write access: .allow_write(\"<path>\")".to_string(),
        ],
    })
}

/// Resource-limit violation inferred from a CPU/memory kill signal.
///
/// On Unix, `SIGXCPU` (CPU time exhausted) and `SIGKILL` (often the
/// out-of-memory killer or a memory cgroup) indicate a resource limit was hit.
/// The suggestion names whichever caps the `config` actually set, so a caller
/// sees a relevant next step. Returns `None` if no resource cap is configured
/// or the death was not from one of these signals.
///
/// This is the shared building block behind the Linux and macOS backends'
/// resource-limit attribution; keeping it here avoids three near-duplicate
/// copies of the same signal/limit heuristic.
#[cfg(unix)]
pub fn resource_signal_violation(config: &SandboxConfig, status: ExitStatus) -> Option<Violation> {
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
        // Killed by SIGXCPU/SIGKILL but no resource limit was set: the signal
        // came from elsewhere (e.g. the OOM killer), so we cannot attribute it.
        return None;
    }

    Some(Violation {
        kind: ViolationKind::ResourceLimit,
        summary: "process was killed by a resource limit (CPU time or memory)".to_string(),
        suggestions,
    })
}
