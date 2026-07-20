//! Declarative sandbox policies.
//!
//! Policies are plain data. Filesystem access starts denied by default. Rules
//! are evaluated in declaration order, and for each independent right the last
//! matching rule wins. Write access does not imply read access, and execute
//! access does not imply read access.

use std::path::PathBuf;

/// A single filesystem rule. Everything beneath `path` is covered.
///
/// By default the sandbox grants no filesystem access at all. Backends must
/// apply exactly the filesystem rules declared here. For each independent
/// right (read, write, execute), rules are evaluated in declaration order and
/// the last matching rule wins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsAccess {
    /// Grant read access to `path` and everything beneath it.
    ReadAllow(PathBuf),
    /// Deny read access to `path` and everything beneath it.
    ReadDeny(PathBuf),
    /// Grant write access to `path` and everything beneath it.
    WriteAllow(PathBuf),
    /// Deny write access to `path` and everything beneath it.
    WriteDeny(PathBuf),
    /// Grant execute access to `path` and everything beneath it.
    ExecuteAllow(PathBuf),
    /// Deny execute access to `path` and everything beneath it.
    ExecuteDeny(PathBuf),
}

/// Network confinement level.
/// Default is [`NetworkPolicy::Deny`].
///
/// Unix-domain sockets are host-local IPC, not network reach, so no level
/// restricts `AF_UNIX`; on Linux, whether creating Unix-domain sockets is
/// allowed is decided by [`IpcPolicy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NetworkPolicy {
    /// Every socket family except `AF_UNIX` is denied.
    #[default]
    Deny,
    /// Outbound IPv4/IPv6 connections are allowed. Every other socket family
    /// except `AF_UNIX` is denied. Whether Unix-domain sockets — servers
    /// included — are available is the local-IPC decision; on Linux that is
    /// [`IpcPolicy`].
    ///
    /// Backends restrict IP-server setup where their native mechanism can
    /// distinguish it from allowed local IPC. On Linux, explicit TCP `bind`
    /// is denied on Landlock ABI v4+, but `listen` on an unbound TCP socket
    /// retains its implicit ephemeral bind. ABI v10+ also denies fixed UDP
    /// binds while allowing port 0; ABI v4-v9 leaves UDP bind unrestricted.
    /// Backend construction fails for this policy on ABI v2-v3. See the Linux
    /// backend documentation for the exact ABI matrix.
    OutboundOnly,
    /// No network restrictions are added.
    Full,
}

/// Linux user-namespace policy.
/// Default is [`UserNamespacePolicy::Deny`].
///
/// **Linux-only.** Enforced with seccomp by the Linux backend; the macOS and
/// Windows backends ignore [`SandboxConfig::linux_user_namespaces`] (neither
/// platform has an equivalent unprivileged facility).
///
/// Creating a user namespace grants the child ambient capabilities inside it,
/// unlocking kernel interfaces (mount machinery, further namespace kinds)
/// that considerably widen the kernel attack surface. No ordinary tool needs
/// this; the notable exception is a child that sets up its own nested sandbox
/// — Chromium/Electron's sandbox, bubblewrap/Flatpak, rootless containers.
///
/// [`SandboxConfig::linux_user_namespaces`]: crate::SandboxConfig::linux_user_namespaces
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UserNamespacePolicy {
    /// Deny creating or joining namespaces: `unshare(CLONE_NEWUSER)`,
    /// `clone(CLONE_NEWUSER)`, and `setns` fail with `EPERM`; `clone3` fails
    /// with `ENOSYS` (seccomp cannot read its flags struct, and the `ENOSYS`
    /// makes runtimes fall back to `clone`, which it can inspect). The mount
    /// machinery (`mount`, `pivot_root`, `chroot`, ...) — only reachable by
    /// unprivileged code inside a user namespace it owns — is denied too.
    #[default]
    Deny,
    /// Permit user-namespace creation and the mount machinery, which the
    /// kernel's own capability checks still deny outside a namespace the
    /// child owns. Set this only when the child runs its own sandbox
    /// (Chromium/Electron, bubblewrap, rootless containers).
    Allow,
}

/// Inter-process-communication confinement level.
/// Default is [`IpcPolicy::Strict`].
///
/// **Linux-only.** This policy is primarily enforced with seccomp by the Linux
/// backend; when relaxed IPC composes with outbound-only networking, Landlock
/// supplies the family-aware TCP-bind restriction. The macOS and Windows
/// backends ignore [`SandboxConfig::linux_ipc`]. On macOS, IPC confinement
/// follows the generated and imported Seatbelt rules, including any
/// Unix-domain socket access enabled by network grants. On Windows,
/// AppContainer baseline isolation applies independently. See each backend
/// crate's documentation.
///
/// [`SandboxConfig::linux_ipc`]: crate::SandboxConfig::linux_ipc
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IpcPolicy {
    /// Deny SysV shared memory / message queues / semaphores, POSIX message
    /// queues, and creating Unix-domain sockets (`socket(AF_UNIX)`, pathname
    /// or abstract) and datagram `socketpair`s, whose endpoints can be
    /// redirected to named sockets. Pipes, connection-oriented `socketpair`s,
    /// anonymous `mmap`, and process inspection inside the sandbox's Landlock
    /// domain remain available. Landlock's implicit ptrace hierarchy denies
    /// inspection of host/outside-domain processes independently.
    #[default]
    Strict,
    /// Permit SysV / POSIX IPC and Unix-domain sockets, including Unix-domain
    /// servers (`bind`/`listen`) — also under [`NetworkPolicy::OutboundOnly`],
    /// which keeps denying explicit TCP `bind` on Linux. Process inspection
    /// works inside the sandbox's Landlock domain; host/outside-domain targets
    /// remain unavailable through Landlock's implicit ptrace hierarchy.
    ///
    /// [`NetworkPolicy::OutboundOnly`]: crate::NetworkPolicy::OutboundOnly
    Relaxed,
}
