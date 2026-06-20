//! Handle to a running sandboxed process.

use std::process::{Child, ExitStatus};

/// A handle to a spawned, sandboxed child process.
///
/// Thin wrapper around [`std::process::Child`]. Backends construct it with
/// `SandboxChild::from`. Observability helpers will consume the exit
/// status alongside the [`SandboxConfig`](crate::SandboxConfig) that produced
/// the child.
#[derive(Debug)]
pub struct SandboxChild {
    inner: Child,
}

impl SandboxChild {
    /// The OS-assigned process id of the child.
    pub fn id(&self) -> u32 {
        self.inner.id()
    }

    /// Wait for the child to exit, returning its status.
    pub fn wait(&mut self) -> std::io::Result<ExitStatus> {
        self.inner.wait()
    }

    /// Attempt to kill the child immediately.
    pub fn kill(&mut self) -> std::io::Result<()> {
        self.inner.kill()
    }

    /// Borrow the underlying [`Child`] (e.g. to take its stdio handles).
    pub fn inner_mut(&mut self) -> &mut Child {
        &mut self.inner
    }

    /// Consume the handle and return the underlying [`Child`].
    pub fn into_inner(self) -> Child {
        self.inner
    }
}

impl From<Child> for SandboxChild {
    fn from(inner: Child) -> Self {
        SandboxChild { inner }
    }
}
