//! The immutable, built sandbox configuration consumed by a [`Backend`].
//!
//! [`Backend`]: crate::Backend

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::policy::{FsAccess, IpcPolicy, NetworkPolicy};

/// Resource limits applied to the sandboxed process tree.
///
/// `None` means "do not impose this limit". Units are chosen to be unambiguous
/// at the API boundary; backends convert to the platform representation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResourceLimits {
    /// Maximum address space (virtual memory) in **bytes**.
    pub memory_bytes: Option<u64>,
    /// Maximum CPU time in **seconds**.
    pub cpu_time_secs: Option<u64>,
    /// Maximum number of processes/threads.
    pub max_processes: Option<u64>,
}

/// A fully-built, immutable sandbox configuration.
///
/// All fields are public so platform backend crates can read them directly.
/// Construct one by filling in the fields directly:
///
/// ```ignore
/// let config = SandboxConfig {
///     fs: vec![],
///     network: NetworkPolicy::Deny,
///     ipc: IpcPolicy::Strict,
///     limits: ResourceLimits::default(),
///     env: BTreeMap::new(),
///     darwin_sandbox_profiles: vec![],
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxConfig {
    /// Filesystem rules, in the order they were declared.
    pub fs: Vec<FsAccess>,
    /// Network confinement level.
    pub network: NetworkPolicy,
    /// IPC confinement level.
    pub ipc: IpcPolicy,
    /// Resource limits.
    pub limits: ResourceLimits,
    /// The **only** environment variables the child will see. The child's
    /// inherited environment is unconditionally cleared before these are
    /// applied — backends expect the command's environment to already be
    /// scrubbed by the caller.
    pub env: BTreeMap<String, String>,
    /// macOS-only Seatbelt profile paths. Non-Darwin backends ignore this field.
    ///
    /// When set, the macOS backend imports these `.sb` profiles before appending
    /// the generated profile from the portable `fs`/`network`/`ipc` policies.
    pub darwin_sandbox_profiles: Vec<PathBuf>,
}
