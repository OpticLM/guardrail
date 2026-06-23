//! The [`SandboxBuilder`] — the primary entry point for callers.

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::config::{ResourceLimits, SandboxConfig};
use crate::policy::{FsAccess, IpcPolicy, NetworkPolicy};

/// Builds a [`SandboxConfig`] using the builder pattern.
///
/// All methods take and return `self` by value for chaining. The default
/// configuration is maximally restrictive: no filesystem access, no network,
/// strict IPC, no resource limits, and an empty environment.
///
/// # Example
/// ```
/// use guardrail_core::{SandboxBuilder, NetworkPolicy};
///
/// let config = SandboxBuilder::new()
///     .allow_read("/tmp/input")
///     .allow_execute("/tmp/tools")
///     .allow_write("/tmp/work")
///     .network(NetworkPolicy::OutboundOnly)
///     .memory_limit_mb(256)
///     .env("PATH", "/usr/bin:/bin")
///     .build();
/// assert_eq!(config.network, NetworkPolicy::OutboundOnly);
/// ```
#[derive(Debug, Clone, Default)]
pub struct SandboxBuilder {
    fs: Vec<FsAccess>,
    network: NetworkPolicy,
    ipc: IpcPolicy,
    limits: ResourceLimits,
    env: BTreeMap<String, String>,
}

impl SandboxBuilder {
    /// Start from the default (maximally restrictive) configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Grant read access to `path` and everything beneath it.
    pub fn allow_read(mut self, path: impl Into<PathBuf>) -> Self {
        self.fs.push(FsAccess::Read(path.into()));
        self
    }

    /// Grant read and write access to `path` and everything beneath it.
    pub fn allow_write(mut self, path: impl Into<PathBuf>) -> Self {
        self.fs.push(FsAccess::Write(path.into()));
        self
    }

    /// Grant execute access to `path` and everything beneath it.
    pub fn allow_execute(mut self, path: impl Into<PathBuf>) -> Self {
        self.fs.push(FsAccess::Execute(path.into()));
        self
    }

    /// Set the network confinement level (last call wins).
    pub fn network(mut self, policy: NetworkPolicy) -> Self {
        self.network = policy;
        self
    }

    /// Set the IPC confinement level (last call wins).
    pub fn ipc(mut self, policy: IpcPolicy) -> Self {
        self.ipc = policy;
        self
    }

    /// Limit address space (virtual memory) to `mb` megabytes.
    pub fn memory_limit_mb(mut self, mb: u64) -> Self {
        self.limits.memory_bytes = Some(mb.saturating_mul(1024 * 1024));
        self
    }

    /// Limit CPU time to `secs` seconds.
    pub fn cpu_time_limit_secs(mut self, secs: u64) -> Self {
        self.limits.cpu_time_secs = Some(secs);
        self
    }

    /// Limit the number of processes/threads.
    pub fn max_processes(mut self, n: u64) -> Self {
        self.limits.max_processes = Some(n);
        self
    }

    /// Add one environment variable to the (otherwise empty) child environment.
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(key.into(), value.into());
        self
    }

    /// Add several environment variables at once.
    pub fn envs<I, K, V>(mut self, vars: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        for (k, v) in vars {
            self.env.insert(k.into(), v.into());
        }
        self
    }

    /// Finalize into an immutable [`SandboxConfig`].
    pub fn build(self) -> SandboxConfig {
        SandboxConfig {
            fs: self.fs,
            network: self.network,
            ipc: self.ipc,
            limits: self.limits,
            env: self.env,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_denies_everything() {
        let config = SandboxBuilder::new().build();
        assert_eq!(config.network, NetworkPolicy::Deny);
        assert_eq!(config.ipc, IpcPolicy::Strict);
        assert!(config.fs.is_empty());
        assert!(config.env.is_empty());
        assert_eq!(config.limits, ResourceLimits::default());
        assert_eq!(config.limits.memory_bytes, None);
        assert_eq!(config.limits.cpu_time_secs, None);
        assert_eq!(config.limits.max_processes, None);
    }

    #[test]
    fn memory_limit_is_expressed_in_bytes() {
        let config = SandboxBuilder::new().memory_limit_mb(2).build();
        assert_eq!(config.limits.memory_bytes, Some(2 * 1024 * 1024));
    }

    #[test]
    fn fs_grants_preserve_declaration_order() {
        let config = SandboxBuilder::new()
            .allow_read("/a")
            .allow_write("/b")
            .allow_execute("/c")
            .build();
        assert_eq!(
            config.fs,
            vec![
                FsAccess::Read(PathBuf::from("/a")),
                FsAccess::Write(PathBuf::from("/b")),
                FsAccess::Execute(PathBuf::from("/c")),
            ]
        );
    }

    #[test]
    fn last_network_call_wins() {
        let config = SandboxBuilder::new()
            .network(NetworkPolicy::Full)
            .network(NetworkPolicy::Deny)
            .build();
        assert_eq!(config.network, NetworkPolicy::Deny);
    }
}
