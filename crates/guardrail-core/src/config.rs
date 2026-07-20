//! The immutable, built sandbox configuration consumed by a [`Backend`].
//!
//! [`Backend`]: crate::Backend

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::policy::{FsAccess, NetworkPolicy, UserNamespacePolicy};

/// Resource limits applied to the sandboxed child.
///
/// `None` means "do not impose this limit". Units are chosen to be unambiguous
/// at the API boundary; backends convert to the platform representation.
///
/// # Platform semantics
///
/// What a limit actually bounds differs per platform:
///
/// - **Windows** applies all three fields to the Job Object, so they are
///   aggregate budgets for the entire sandboxed process tree.
/// - **Linux and macOS** apply per-process `setrlimit(2)` caps in the child
///   before exec. Descendants inherit the same caps, but each process is
///   limited independently: a child that forks N workers can consume up to
///   N times `memory_bytes` / `cpu_time_secs` in aggregate.
/// - On Linux and macOS `max_processes` maps to `RLIMIT_NPROC`, which counts
///   all processes (on Linux, also threads) of the real user ID system-wide,
///   not just the sandboxed tree, and is not enforced for privileged users
///   (root, or Linux `CAP_SYS_RESOURCE`/`CAP_SYS_ADMIN`).
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
///     limits: ResourceLimits::default(),
///     env: BTreeMap::new(),
///     linux_unix_sockets: vec![],
///     linux_user_namespaces: UserNamespacePolicy::Deny,
///     darwin_sandbox_profiles: vec![],
///     windows_cache_namespace: None,
/// };
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SandboxConfig {
    /// Filesystem rules, in the order they were declared.
    pub fs: Vec<FsAccess>,
    /// Network confinement level.
    pub network: NetworkPolicy,
    /// Resource limits.
    pub limits: ResourceLimits,
    /// The **only** environment variables the child will see. The child's
    /// inherited environment is unconditionally cleared before these are
    /// applied by the backend.
    ///
    /// The Windows backend also resolves bare program names against this
    /// environment's `PATH` — never the parent's — so the configuration alone
    /// determines which binary is launched. Every non-empty Windows `PATH`
    /// entry must be absolute; a relative entry makes bare-program spawning
    /// fail with `InvalidInput` (see the backend crate docs).
    pub env: BTreeMap<String, String>,
    /// Linux-only grants for connecting or sending to host-created pathname
    /// Unix sockets. Non-Linux backends ignore this field.
    ///
    /// Each entry identifies either one socket path or a path hierarchy. These
    /// grants are independent of [`FsAccess`]: filesystem read/write access
    /// never grants socket connection access, and a socket grant never grants
    /// file access.
    ///
    /// The Linux backend uses this field only on Landlock ABI v9 and newer. On
    /// those kernels, host-created pathname sockets are denied by default and
    /// entries here grant `LANDLOCK_ACCESS_FS_RESOLVE_UNIX` beneath the named
    /// path. The paths must exist when a child is spawned. On ABI v2-v8 the
    /// kernel cannot mediate pathname-socket connections, so the backend does
    /// not validate or open these entries and pathname sockets remain
    /// unrestricted by this field.
    ///
    /// A service reached through a granted socket can pass file descriptors
    /// with `SCM_RIGHTS`. Those descriptors retain the access of the already
    /// open host objects they refer to, independently of [`FsAccess`]. Treat a
    /// socket grant as trust in the service and the capabilities it may send.
    pub linux_unix_sockets: Vec<PathBuf>,
    /// Linux-only user-namespace policy. Non-Linux backends ignore this field.
    ///
    /// Enforced with seccomp by the Linux backend. Denied by default; allow it
    /// only when the child runs its own nested sandbox (Chromium/Electron,
    /// bubblewrap, rootless containers). See [`UserNamespacePolicy`].
    pub linux_user_namespaces: UserNamespacePolicy,
    /// macOS-only Seatbelt profile paths. Non-Darwin backends ignore this field.
    ///
    /// When set, the macOS backend imports these `.sb` profiles before appending
    /// the generated profile from the portable `fs`/`network` policies.
    ///
    /// # Security
    ///
    /// Imported profiles are trusted policy extensions, not policy fragments
    /// constrained by `fs` or `network`. An imported `allow` can grant access
    /// absent from the portable policy, including filesystem paths omitted from
    /// `fs`; the later generated `(deny default)` does not revoke that access.
    /// Review every profile and its transitive imports, and keep profile files
    /// outside paths writable by the sandboxed child.
    pub darwin_sandbox_profiles: Vec<PathBuf>,
    /// Windows-only cache namespace for reusable AppContainer profiles and ACLs.
    ///
    /// Use distinct namespaces for sandboxes whose filesystem policies may be
    /// active at the same time. Non-Windows backends ignore this field.
    pub windows_cache_namespace: Option<String>,
}
