//! The platform-confinement abstraction.

use crate::command::SandboxCommand;
use crate::error::Result;
use crate::process::SandboxChild;

/// A platform-specific sandbox backend.
///
/// Implementors apply OS-level confinement (filesystem, network, IPC, resource
/// limits) and spawn the child according to the immutable configuration they
/// were constructed with. A [`SandboxCommand`] carries no environment by
/// construction, so the child's environment is exactly the configuration's
/// `env`; backends that go through [`std::process::Command`] must still clear
/// its inherited environment before applying that map (see
/// [`SandboxCommand::into_std_command`]). A backend must also keep the
/// parent's file descriptors or handles from leaking into the child: only the
/// standard streams selected by the command's
/// [`StdioMode`](crate::StdioMode)s may cross the sandbox boundary. Policies
/// cannot revoke access to descriptors that are already open, so an inherited
/// descriptor would bypass them.
pub trait Backend {
    /// Probe whether the running machine appears to support this backend.
    ///
    /// Returns [`Error::Unsupported`] when a required OS or kernel feature
    /// cannot be probed. A successful probe is not proof that a later spawn
    /// will succeed: runtime state or an ambient sandbox may still block
    /// confinement. In particular, Linux only probes whether the kernel
    /// reports the seccomp `Trap` action; it cannot prove that installing the
    /// filter will be permitted at spawn time. Spawning remains authoritative
    /// and fails closed when confinement cannot be applied, so calling
    /// this first is optional. It exists to let applications detect known
    /// incompatibilities up front and degrade deliberately.
    ///
    /// [`Error::Unsupported`]: crate::Error::Unsupported
    fn probe_support() -> Result<()>
    where
        Self: Sized;

    /// Spawn `command` confined according to this backend's stored config.
    fn spawn(&self, command: SandboxCommand) -> Result<SandboxChild>;
}
