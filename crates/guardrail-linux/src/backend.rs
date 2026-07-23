use std::os::unix::process::CommandExt;

use guardrail_core::{Backend, Error, Result, SandboxChild, SandboxCommand, SandboxConfig};

use crate::{fs, ipc, net, ns, rlimit, seccomp, support};

/// The Linux sandbox backend.
pub struct LinuxBackend {
    config: SandboxConfig,
    fs_rules: fs::CompiledRules,
    ipc_policy: ipc::Policy,
    net_ruleset: Option<fs::PreparedRuleset>,
    seccomp_programs: Vec<seccompiler::BpfProgram>,
}

impl LinuxBackend {
    /// Create a new Linux backend.
    ///
    /// Fails closed with [`Error::Unsupported`] when the running kernel cannot
    /// enforce Landlock ABI v2 (Linux 5.19+, required so write grants honor
    /// cross-directory rename and link) or fails the seccomp
    /// action-availability probe (see
    /// [`Backend::probe_support`]); when `NetworkPolicy::OutboundOnly` is
    /// requested and the kernel lacks Landlock network support (ABI v4,
    /// Linux 6.7+; see the crate-level ABI table);
    /// or when the host forbids the unprivileged IPC/user/mount namespaces
    /// required for every sandbox's IPC isolation (see the crate-level
    /// namespace documentation).
    pub fn new(config: SandboxConfig) -> Result<Self> {
        Self::probe_support()?;
        let fs_rules = fs::compile(&config.fs)?;
        ns::probe_namespace_support()?;
        let ipc_policy = ipc::Policy::new(&config)?;
        let net_ruleset = net::prepare(&config)?;
        let seccomp_programs = seccomp::build(&config)?;
        Ok(Self {
            config,
            fs_rules,
            ipc_policy,
            net_ruleset,
            seccomp_programs,
        })
    }
}

impl Backend for LinuxBackend {
    fn probe_support() -> Result<()> {
        support::probe_required_features()
    }

    fn spawn(&self, command: SandboxCommand) -> Result<SandboxChild> {
        // `into_std_command` applies program, args, cwd, and stdio, and clears
        // the inherited environment; the configuration env is the only one the
        // child sees.
        let mut command = command.into_std_command();
        command.envs(&self.config.env);

        // Everything the child needs crosses the fork as plain bytes or file
        // descriptors prepared here in the parent: all host-path Landlock
        // rules (rule compilation, PathFd opens, add_rule) are built before
        // fork(), the BPF programs were compiled in `new`, and the namespace
        // plan is CStrings and fixed buffers compiled in `new`. The child
        // adds only its freshly mounted private IPC filesystems to Landlock.
        let limits = self.config.limits;
        let landlock_ruleset = fs::prepare(&self.fs_rules)?;
        let ipc_ruleset = self.ipc_policy.prepare()?;
        let net_ruleset = self
            .net_ruleset
            .as_ref()
            .map(fs::PreparedRuleset::try_clone)
            .transpose()?;
        let seccomp_programs = self.seccomp_programs.clone();
        let mut namespace = ns::PreparedNamespace::new(&self.fs_rules.mount_plan);

        // SAFETY: the closure runs after fork() and before execvp() in the
        // child of a possibly multithreaded parent, so it may only use
        // async-signal-safe operations. Every step below is a raw syscall
        // over data captured from the parent, and every error is an
        // errno-backed io::Error — no allocation, locks, or formatting after
        // fork. It returns an io::Error instead of panicking.
        unsafe {
            command.pre_exec(move || {
                // (1) NO_NEW_PRIVS first: required for Landlock and seccomp
                //     below, and a hardening measure on its own. prctl is
                //     async-signal-safe.
                set_no_new_privs()?;

                // (2) Enter fresh IPC/user/mount namespaces, mount private
                //     /dev/mqueue and /dev/shm filesystems, and install any
                //     deny-under-allow mount masks. This must precede
                //     Landlock, which denies mount-topology changes once
                //     enforced. The forked child is single-threaded, as
                //     unshare(CLONE_NEWUSER) requires.
                namespace.enter()?;

                // (3) Resource limits.
                rlimit::apply(&limits)?;

                // (4) Grant the newly mounted private IPC filesystems in this
                //     spawn's parent-built Landlock ruleset, then enforce it.
                //     Their host counterparts are already hidden and are
                //     never referenced by these rules.
                landlock_ruleset.allow_private_ipc()?;
                landlock_ruleset.restrict_self()?;

                // (4b) Network confinement for OutboundOnly: a second
                //     parent-built Landlock layer denies explicit TCP bind
                //     and, on ABI v10+, fixed UDP bind (see crate::net).
                if let Some(net_ruleset) = &net_ruleset {
                    net_ruleset.restrict_self()?;
                }

                // (4c) Create the sandbox's IPC domain. On ABI v6+ this
                //     scopes abstract Unix sockets and signals; on ABI v9+
                //     it additionally mediates host pathname Unix sockets.
                //     Applying this layer last keeps every process and socket
                //     the child creates within the same or a nested domain.
                if let Some(ipc_ruleset) = &ipc_ruleset {
                    ipc_ruleset.restrict_self()?;
                }

                // (5) Descriptor hygiene: mark everything above stderr
                //     close-on-exec. Runs after the steps above so descriptors
                //     they hold along the way are covered too, and before
                //     seccomp so the filter cannot interfere with the syscall.
                scrub_inherited_fds()?;

                // (6) Seccomp is applied LAST so its filters do not interfere
                //     with the syscalls above. The BPF programs were built in
                //     the parent; only prctl(2) + seccomp(2) happen here.
                seccomp::apply(&seccomp_programs)?;

                Ok(())
            });
        }

        let child = command.spawn().map_err(Error::Spawn)?;
        Ok(SandboxChild::from(child))
    }
}

/// `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)`. Async-signal-safe.
fn set_no_new_privs() -> std::io::Result<()> {
    // SAFETY: prctl with PR_SET_NO_NEW_PRIVS takes scalar args only.
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Mark every descriptor above stderr close-on-exec so `execve` closes them
/// atomically. Landlock and seccomp cannot revoke access to descriptors the
/// parent already holds open (files, sockets, pipes), so an inherited
/// descriptor would bypass the whole policy.
///
/// Descriptors are flagged rather than closed because the standard library's
/// fork/exec machinery still needs its (already close-on-exec) exec-error
/// pipe after this closure returns; stdio was `dup2`ed onto 0–2 before any
/// `pre_exec` closure runs, so it is unaffected. `close_range(2)` is
/// async-signal-safe; `CLOSE_RANGE_CLOEXEC` exists since Linux 5.11, and every
/// kernel that passes the Landlock probe (5.19+) has it, so there is no
/// fallback path — fail closed instead. The raw syscall avoids the glibc
/// 2.34+ / musl wrapper requirement.
fn scrub_inherited_fds() -> std::io::Result<()> {
    // SAFETY: close_range takes scalar args only and touches no memory.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_close_range,
            3,
            libc::c_uint::MAX,
            libc::CLOSE_RANGE_CLOEXEC,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
