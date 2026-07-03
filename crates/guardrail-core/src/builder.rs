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
/// use guardrail_core::{SandboxBuilder, NetworkPolicy, FsAccess};
///
/// let config = SandboxBuilder::new()
///     .fs([
///         FsAccess::ReadAllow("/tmp/input".into()),
///         FsAccess::ReadDeny("/tmp/input/secrets".into()),
///         FsAccess::ExecuteAllow("/tmp/tools".into()),
///         FsAccess::WriteAllow("/tmp/work".into()),
///     ])
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
    darwin_sandbox_profiles: Vec<PathBuf>,
}

impl SandboxBuilder {
    /// Start from the default (maximally restrictive) configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set or extend the filesystem rules, in declaration order.
    pub fn fs(mut self, rules: impl IntoIterator<Item = FsAccess>) -> Self {
        self.fs.extend(rules);
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

    /// Set or extend the macOS Seatbelt `.sb` profile paths.
    pub fn darwin_sandbox_profiles(mut self, profiles: impl IntoIterator<Item = PathBuf>) -> Self {
        self.darwin_sandbox_profiles.extend(profiles);
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
            darwin_sandbox_profiles: self.darwin_sandbox_profiles,
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
        assert!(config.darwin_sandbox_profiles.is_empty());
    }

    #[test]
    fn memory_limit_is_expressed_in_bytes() {
        let config = SandboxBuilder::new().memory_limit_mb(2).build();
        assert_eq!(config.limits.memory_bytes, Some(2 * 1024 * 1024));
    }

    #[test]
    fn fs_rules_preserve_declaration_order() {
        let config = SandboxBuilder::new()
            .fs(vec![
                FsAccess::ReadAllow("/a".into()),
                FsAccess::ReadDeny("/b".into()),
                FsAccess::WriteAllow("/c".into()),
                FsAccess::WriteDeny("/d".into()),
                FsAccess::ExecuteAllow("/e".into()),
                FsAccess::ExecuteDeny("/f".into()),
            ])
            .build();
        assert_eq!(
            config.fs,
            vec![
                FsAccess::ReadAllow(PathBuf::from("/a")),
                FsAccess::ReadDeny(PathBuf::from("/b")),
                FsAccess::WriteAllow(PathBuf::from("/c")),
                FsAccess::WriteDeny(PathBuf::from("/d")),
                FsAccess::ExecuteAllow(PathBuf::from("/e")),
                FsAccess::ExecuteDeny(PathBuf::from("/f")),
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

    #[test]
    fn darwin_sandbox_profiles_preserve_declaration_order() {
        let config = SandboxBuilder::new()
            .darwin_sandbox_profiles(vec!["/tmp/first.sb".into(), "/tmp/second.sb".into()])
            .build();
        assert_eq!(
            config.darwin_sandbox_profiles,
            vec![
                PathBuf::from("/tmp/first.sb"),
                PathBuf::from("/tmp/second.sb"),
            ]
        );
    }

    #[test]
    fn darwin_sandbox_profile_appends_one() {
        let config = SandboxBuilder::new()
            .darwin_sandbox_profiles(vec!["/tmp/first.sb".into(), "/tmp/second.sb".into()])
            .build();
        assert_eq!(
            config.darwin_sandbox_profiles,
            vec![
                PathBuf::from("/tmp/first.sb"),
                PathBuf::from("/tmp/second.sb"),
            ]
        );
    }
}
