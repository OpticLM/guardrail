//! Declarative sandbox policies.
//!
//! Policies are plain data. They describe *what is allowed*; everything not
//! granted is denied by default.

use std::path::PathBuf;

/// A single filesystem grant. Everything beneath `path` is covered.
///
/// By default the sandbox grants no filesystem access at all. Backends must
/// apply exactly the filesystem grants declared here; callers that need to run
/// a binary or load shared libraries must grant the required read and execute
/// access explicitly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsAccess {
    /// Grant read access to `path` and everything beneath it.
    Read(PathBuf),
    /// Grant read and write access to `path` and everything beneath it.
    Write(PathBuf),
    /// Grant execute access to `path` and everything beneath it.
    Execute(PathBuf),
}

/// Network confinement level.
/// Default is [`NetworkPolicy::Deny`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NetworkPolicy {
    /// No network access of any kind.
    #[default]
    Deny,
    /// Outbound connections allowed; binding/listening still denied.
    OutboundOnly,
    /// Outbound connections **and** binding/listening allowed.
    Full,
}

/// Inter-process-communication confinement level.
/// Default is [`IpcPolicy::Strict`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IpcPolicy {
    /// Deny cross-process IPC: SysV shared memory / message queues /
    /// semaphores, POSIX message queues, and process inspection (`ptrace`,
    /// `process_vm_*`). Benign same-process primitives (pipes, `socketpair`,
    /// anonymous `mmap`) remain available.
    #[default]
    Strict,
    /// Like `Strict`, but additionally permit shared memory and POSIX message
    /// queues. Process inspection (`ptrace`, `process_vm_*`) stays denied.
    Relaxed,
}
