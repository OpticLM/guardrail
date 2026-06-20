//! Best-effort observability for policy violations.
//!
//! These types describe *why a sandboxed process likely failed* and *which
//! policy to add*. They are heuristic: the parent process cannot observe the
//! exact syscall or path a backend denied, so a [`Violation`] narrows the
//! cause from the exit status and the active configuration rather than
//! pinpointing it. Backends (e.g. `guardrail-linux`) produce these.

use std::fmt;

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
