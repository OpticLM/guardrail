//! The immutable, built sandbox configuration consumed by a [`Backend`].
//!
//! [`Backend`]: crate::Backend

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::backend::Backend;
use crate::error::Error;
use crate::policy::{FsAccess, IpcPolicy, NetworkPolicy};
use crate::process::SandboxChild;

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
/// Produced by [`SandboxBuilder::build`](crate::SandboxBuilder::build). Fields
/// are public so platform backend crates can read them directly.
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
    /// applied (see [`SandboxConfig::spawn_with`]).
    pub env: BTreeMap<String, String>,
    /// macOS-only Seatbelt profile paths. Non-Darwin backends ignore this field.
    ///
    /// When set, the macOS backend imports these `.sb` profiles before appending
    /// the generated profile from the portable `fs`/`network`/`ipc` policies.
    pub darwin_sandbox_profiles: Vec<PathBuf>,
}

impl SandboxConfig {
    /// Spawn `command` under `backend`, applying this configuration.
    ///
    /// This clears every inherited environment variable and
    /// injecting only `self.env` — and then delegates platform confinement to
    /// the backend. Doing the scrub here guarantees it happens no matter which
    /// backend is used.
    pub fn spawn_with<B: Backend>(
        &self,
        backend: &B,
        mut command: std::process::Command,
    ) -> Result<SandboxChild, Error> {
        command.env_clear();
        command.envs(&self.env);
        backend.spawn(self, command)
    }
}
