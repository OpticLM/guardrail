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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NetworkPolicy {
    /// Only Unix-domain sockets are allowed; every other socket family is
    /// denied.
    #[default]
    Deny,
    /// Unix-domain sockets and outbound IPv4/IPv6 connections are allowed.
    /// Other socket families and binding/listening are denied.
    OutboundOnly,
    /// No network restrictions are added.
    Full,
}

/// Inter-process-communication confinement level.
/// Default is [`IpcPolicy::Strict`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IpcPolicy {
    /// Deny SysV shared memory / message queues / semaphores, POSIX message
    /// queues, and process inspection (`ptrace`, `process_vm_*`). Pipes,
    /// Unix-domain sockets (including `socketpair`), and anonymous `mmap`
    /// remain available.
    #[default]
    Strict,
    /// Permit SysV and POSIX IPC. Process inspection (`ptrace`,
    /// `process_vm_*`) stays denied.
    Relaxed,
}
