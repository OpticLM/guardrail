use std::mem::MaybeUninit;
use std::os::unix::process::CommandExt;
use std::process::Command;

use guardrail_core::{Backend, Error, Result, SandboxChild, SandboxConfig};

use crate::{rlimit, seatbelt};

/// The macOS sandbox backend.
pub struct MacosBackend {
    config: SandboxConfig,
    seatbelt_profile: seatbelt::PreparedProfile,
}

impl MacosBackend {
    /// Create a new macOS backend.
    pub fn new(config: SandboxConfig) -> Result<Self> {
        let seatbelt_profile = seatbelt::prepare(seatbelt::resolve(&config)?)?;
        Ok(Self {
            config,
            seatbelt_profile,
        })
    }
}

impl Backend for MacosBackend {
    /// Seatbelt (`sandbox_init`) and `setrlimit` exist on every macOS version
    /// this crate compiles for, so support is unconditional.
    fn probe_support() -> Result<()> {
        Ok(())
    }

    fn spawn(&self, mut command: Command) -> Result<SandboxChild> {
        command.env_clear();
        command.envs(&self.config.env);

        let seatbelt_profile = self.seatbelt_profile.clone();
        let limits = self.config.limits;
        let mut inherited_fds = InheritedFdTable::new()
            .map_err(|err| Error::confinement("file-descriptor hygiene", err))?;

        // SAFETY: the closure runs after fork() and before execvp() in the
        // child. All buffers and the Seatbelt C string were allocated in the
        // parent; the closure itself only calls libc functions over captured
        // storage and returns io::Error values with raw OS codes.
        unsafe {
            command.pre_exec(move || {
                // Descriptor hygiene first: it must precede Seatbelt, whose
                // profile may deny process-info queries.
                inherited_fds.scrub()?;
                rlimit::apply(&limits)?;
                seatbelt::apply(&seatbelt_profile)?;
                Ok(())
            });
        }

        let child = command.spawn().map_err(Error::Spawn)?;
        Ok(SandboxChild::from(child))
    }
}

/// Parent-allocated storage for an exact snapshot of the fork child's open
/// descriptors. macOS has no `close_range(2)`, while directory traversal is
/// not safe after a multi-threaded `fork` because it allocates and takes locks.
struct InheritedFdTable {
    entries: Vec<MaybeUninit<libc::proc_fdinfo>>,
    buffer_bytes: libc::c_int,
}

impl InheritedFdTable {
    /// Allocate enough room in the parent for every descriptor the child can
    /// hold. The current process query also covers descriptors above a limit
    /// that the parent lowered after opening them.
    fn new() -> std::io::Result<Self> {
        // SAFETY: getdtablesize takes no arguments and only reads process state.
        let descriptor_limit = unsafe { libc::getdtablesize() };
        if descriptor_limit < 0 {
            return Err(std::io::Error::last_os_error());
        }

        // A null buffer asks the kernel for the current file-table size (with
        // its own growth margin). This call runs in the parent and allocates no
        // user-space memory.
        // SAFETY: the null buffer and zero size are the documented sizing form.
        let current_bytes = unsafe {
            libc::proc_pidinfo(
                libc::getpid(),
                libc::PROC_PIDLISTFDS,
                0,
                std::ptr::null_mut(),
                0,
            )
        };
        if current_bytes <= 0 {
            return Err(std::io::Error::last_os_error());
        }

        let entry_size = std::mem::size_of::<libc::proc_fdinfo>();
        let limit_bytes = (descriptor_limit as usize)
            .checked_mul(entry_size)
            .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EOVERFLOW))?;
        let requested_bytes = limit_bytes.max(current_bytes as usize);
        let entry_count = requested_bytes.div_ceil(entry_size);
        let buffer_bytes = entry_count
            .checked_mul(entry_size)
            .and_then(|bytes| libc::c_int::try_from(bytes).ok())
            .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EOVERFLOW))?;

        let mut entries = Vec::with_capacity(entry_count);
        entries.resize_with(entry_count, MaybeUninit::uninit);
        Ok(Self {
            entries,
            buffer_bytes,
        })
    }

    /// Mark every descriptor above stderr close-on-exec so `execve` closes it
    /// atomically. The buffer and all bookkeeping were prepared in the parent;
    /// Apple's `proc_pidinfo(PROC_PIDLISTFDS)` wrapper is a direct system call.
    fn scrub(&mut self) -> std::io::Result<()> {
        // SAFETY: entries points to buffer_bytes of writable captured storage.
        let populated_bytes = unsafe {
            libc::proc_pidinfo(
                libc::getpid(),
                libc::PROC_PIDLISTFDS,
                0,
                self.entries.as_mut_ptr().cast(),
                self.buffer_bytes,
            )
        };
        if populated_bytes <= 0 {
            return Err(std::io::Error::last_os_error());
        }

        let entry_size = std::mem::size_of::<libc::proc_fdinfo>();
        let populated_bytes = populated_bytes as usize;
        if populated_bytes > self.buffer_bytes as usize
            || !populated_bytes.is_multiple_of(entry_size)
        {
            return Err(std::io::Error::from_raw_os_error(libc::EIO));
        }

        for entry in &self.entries[..populated_bytes / entry_size] {
            // SAFETY: proc_pidinfo initialized every complete returned record.
            let fd = unsafe { entry.assume_init_ref() }.proc_fd;
            if fd <= 2 {
                continue;
            }

            // SAFETY: fcntl with F_GETFD/F_SETFD takes scalar arguments only.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            if flags < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EBADF) {
                    continue;
                }
                return Err(err);
            }
            if (flags & libc::FD_CLOEXEC) == 0 {
                // SAFETY: as above.
                let rc = unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
                if rc < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use guardrail_core::{IpcPolicy, NetworkPolicy, ResourceLimits, SandboxConfig};

    #[test]
    fn crate_smoke_test_builds_a_default_config() {
        let config = SandboxConfig {
            fs: vec![],
            network: NetworkPolicy::Deny,
            ipc: IpcPolicy::Strict,
            limits: ResourceLimits::default(),
            env: BTreeMap::new(),
            darwin_sandbox_profiles: vec![],
            windows_cache_namespace: None,
        };
        assert!(config.fs.is_empty());
    }
}
