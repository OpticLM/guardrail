//! Network, IPC, and kernel-attack-surface confinement via seccomp-BPF
//! denylists.
//!
//! Default action is Allow (arbitrary shell tools must keep working); specific
//! syscalls/arguments are mapped to `VIOLATION_ACTION`. Trap is used so a
//! violation terminates the child with SIGSYS, which the parent can observe.
//! Network rules live here; IPC rules are added to the same filter via
//! `add_ipc_rules`, and kernel-interface syscalls no shell tool legitimately
//! calls (kernel code loading, keyring, host-state interference, and — under
//! `UserNamespacePolicy::Deny` — the mount machinery) via
//! `add_kernel_surface_rules`.
//!
//! Three more filters are stacked as needed; the kernel runs every installed
//! filter and applies the highest-precedence action (Trap > Errno > Allow):
//!
//! * Kernel interfaces that legitimate tooling probes and must fall back from
//!   gracefully — `bpf`, `perf_event_open`, `userfaultfd`, plus namespace
//!   creation/joining under `UserNamespacePolicy::Deny` — fail with `EPERM`,
//!   the same errno an unprivileged caller sees from a hardened kernel.
//!
//! * Under `IpcPolicy::Strict`, creating a Unix-domain socket — the road to
//!   local services such as D-Bus or container engines, whether by pathname
//!   or abstract name — fails with `EAFNOSUPPORT`. Errno rather than Trap
//!   because well-behaved tools opportunistically probe optional local
//!   sockets (nscd, syslog, ssh-agent) and must fall back instead of dying.
//!   Datagram `socketpair`s are denied too because either endpoint can be
//!   redirected to a named socket with `connect` or `sendto`.
//!   Connection-oriented `socketpair`s stay available.
//!
//! * io_uring is denied with `ENOSYS` unless both policies are at their most
//!   permissive level: ring-submitted operations (`IORING_OP_SOCKET`,
//!   `IORING_OP_CONNECT`, `IORING_OP_BIND`, ...) are not syscalls, so leaving
//!   io_uring available would bypass the socket rules. With `ENOSYS` — not
//!   Trap — runtimes that probe io_uring for file I/O (libuv/Node,
//!   tokio-uring) see a kernel without io_uring and fall back to plain
//!   syscalls, which the other filters do govern. `clone3` joins this filter
//!   under `UserNamespacePolicy::Deny`: its flags live in a struct seccomp
//!   cannot read, and `ENOSYS` makes glibc and other runtimes fall back to
//!   plain `clone`, whose flags the `EPERM` filter can inspect.

use std::collections::BTreeMap;
use std::convert::TryInto;

use guardrail_core::{Error, IpcPolicy, NetworkPolicy, Result, SandboxConfig, UserNamespacePolicy};
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule,
};

/// Action taken when a denied syscall is attempted. Trap -> SIGSYS (observable
/// by the parent). Change to `SeccompAction::Errno(libc::EACCES as u32)` for
/// graceful per-call failure instead of process termination.
const VIOLATION_ACTION: SeccompAction = SeccompAction::Trap;

/// Low bits containing the base socket type. `SOCK_NONBLOCK` and
/// `SOCK_CLOEXEC` live above this mask and may be ORed into the type argument.
const SOCKET_TYPE_MASK: u64 = 0xf;

type RuleMap = BTreeMap<i64, Vec<SeccompRule>>;

/// x32 uses the x86-64 audit architecture but sets bit 30 in the syscall
/// number. Seccomp rules must therefore cover both ABIs on x86-64.
#[cfg(target_arch = "x86_64")]
const X32_SYSCALL_BIT: i64 = 0x4000_0000;

// Legacy x32 entries whose base numbers differ from native x86-64.
#[cfg(target_arch = "x86_64")]
const X32_SYS_PTRACE: i64 = 521;
#[cfg(target_arch = "x86_64")]
const X32_SYS_MQ_NOTIFY: i64 = 527;
#[cfg(target_arch = "x86_64")]
const X32_SYS_KEXEC_LOAD: i64 = 528;
#[cfg(target_arch = "x86_64")]
const X32_SYS_PROCESS_VM_READV: i64 = 539;
#[cfg(target_arch = "x86_64")]
const X32_SYS_PROCESS_VM_WRITEV: i64 = 540;

// 294 is the asm-generic slot. libc omits the constant on aarch64-musl and on
// riscv64, where the syscall is not currently implemented.
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const SYS_KEXEC_FILE_LOAD: i64 = 294;
#[cfg(not(any(target_arch = "aarch64", target_arch = "riscv64")))]
const SYS_KEXEC_FILE_LOAD: i64 = libc::SYS_kexec_file_load;

/// Kernel-interface syscalls no LLM-run tool legitimately calls, denied at
/// `VIOLATION_ACTION` regardless of policy: kernel code loading, the kernel
/// keyring, and host-state interference. `NO_NEW_PRIVS` already blocks the
/// setuid road to the privileges these need, but the syscalls themselves
/// remain kernel attack surface worth removing outright.
const KERNEL_SURFACE_SYSCALLS: &[i64] = &[
    // Kernel code loading
    libc::SYS_kexec_load,
    SYS_KEXEC_FILE_LOAD,
    libc::SYS_init_module,
    libc::SYS_finit_module,
    libc::SYS_delete_module,
    // Kernel keyring
    libc::SYS_add_key,
    libc::SYS_request_key,
    libc::SYS_keyctl,
    // Host-state interference
    libc::SYS_reboot,
    libc::SYS_swapon,
    libc::SYS_swapoff,
    libc::SYS_acct,
];

/// Mount-machinery syscalls, denied at `VIOLATION_ACTION` under
/// `UserNamespacePolicy::Deny`. Unprivileged code can only exercise these
/// inside a user namespace it owns, so denying them costs nothing then; under
/// `Allow` they stay available because a nested sandbox (bubblewrap,
/// Chromium) is exactly a user namespace plus mount surgery, and outside an
/// owned namespace the kernel's capability checks still refuse them.
const MOUNT_SYSCALLS: &[i64] = &[
    libc::SYS_mount,
    libc::SYS_umount2,
    libc::SYS_move_mount,
    libc::SYS_fsopen,
    libc::SYS_fsconfig,
    libc::SYS_fsmount,
    libc::SYS_fspick,
    libc::SYS_open_tree,
    libc::SYS_mount_setattr,
    libc::SYS_pivot_root,
    libc::SYS_chroot,
];

/// Kernel interfaces denied with `EPERM` rather than Trap: legitimate tools
/// (tracers, runtimes) probe these and must fall back gracefully, and a
/// hardened kernel hands unprivileged callers the same errno.
const PROBED_KERNEL_SYSCALLS: &[i64] = &[
    libc::SYS_bpf,
    libc::SYS_perf_event_open,
    libc::SYS_userfaultfd,
];

/// Syscalls blocked only at the `Strict` level (SysV IPC + POSIX mqueue).
const STRICT_ONLY_IPC: &[i64] = &[
    // SysV shared memory
    libc::SYS_shmget,
    libc::SYS_shmat,
    libc::SYS_shmdt,
    libc::SYS_shmctl,
    // SysV message queues
    libc::SYS_msgget,
    libc::SYS_msgsnd,
    libc::SYS_msgrcv,
    libc::SYS_msgctl,
    // SysV semaphores
    libc::SYS_semget,
    libc::SYS_semop,
    libc::SYS_semtimedop,
    libc::SYS_semctl,
    // POSIX message queues
    libc::SYS_mq_open,
    libc::SYS_mq_unlink,
    libc::SYS_mq_timedsend,
    libc::SYS_mq_timedreceive,
    libc::SYS_mq_notify,
    libc::SYS_mq_getsetattr,
];

/// Process-inspection syscalls blocked at BOTH levels. Never benign for a
/// sandbox: they let code read/modify other processes' memory.
const ALWAYS_BLOCKED_IPC: &[i64] = &[
    libc::SYS_ptrace,
    libc::SYS_process_vm_readv,
    libc::SYS_process_vm_writev,
];

/// io_uring syscalls, denied with `ENOSYS` unless the network policy is
/// `Full` and the IPC policy is `Relaxed`. Operations submitted through a
/// ring never pass the syscall filter, so neither the socket-family rules nor
/// the `AF_UNIX` rule can see them. `enter` and `register` are included
/// besides `setup` so an inherited or fd-passed ring is equally unusable.
const IO_URING_SYSCALLS: &[i64] = &[
    libc::SYS_io_uring_setup,
    libc::SYS_io_uring_enter,
    libc::SYS_io_uring_register,
];

/// Build the seccomp filters for `config`.
pub(crate) fn build(config: &SandboxConfig) -> Result<Vec<BpfProgram>> {
    let mut programs = Vec::new();

    programs.push(compile(violation_rules(config)?, VIOLATION_ACTION)?);
    programs.push(compile(
        probed_kernel_rules(config)?,
        SeccompAction::Errno(libc::EPERM as u32),
    )?);

    if config.linux_ipc == IpcPolicy::Strict {
        programs.push(compile(
            unix_socket_rules()?,
            SeccompAction::Errno(libc::EAFNOSUPPORT as u32),
        )?);
    }

    let enosys = enosys_rules(config);
    if !enosys.is_empty() {
        programs.push(compile(enosys, SeccompAction::Errno(libc::ENOSYS as u32))?);
    }

    Ok(programs)
}

/// Rules mapped to `VIOLATION_ACTION`: network policy, IPC policy, and the
/// unconditional kernel-attack-surface denylist.
fn violation_rules(config: &SandboxConfig) -> Result<RuleMap> {
    let mut rules = RuleMap::new();
    add_network_rules(&mut rules, config.network)?;
    add_ipc_rules(&mut rules, config.linux_ipc)?;
    add_kernel_surface_rules(&mut rules, config.linux_user_namespaces);
    Ok(rules)
}

fn add_kernel_surface_rules(rules: &mut RuleMap, policy: UserNamespacePolicy) {
    for &sys in KERNEL_SURFACE_SYSCALLS {
        add_whole_syscall_rule(rules, sys);
    }
    if policy == UserNamespacePolicy::Deny {
        for &sys in MOUNT_SYSCALLS {
            add_whole_syscall_rule(rules, sys);
        }
    }
}

/// Rules mapped to `Errno(EPERM)`: kernel interfaces that legitimate tools
/// probe, plus namespace creation/joining under `UserNamespacePolicy::Deny`.
fn probed_kernel_rules(config: &SandboxConfig) -> Result<RuleMap> {
    let mut rules = RuleMap::new();
    for &sys in PROBED_KERNEL_SYSCALLS {
        add_whole_syscall_rule(&mut rules, sys);
    }
    if config.linux_user_namespaces == UserNamespacePolicy::Deny {
        let newuser = clone_newuser_rule()?;
        add_syscall_rule(&mut rules, libc::SYS_unshare, newuser.clone());
        add_syscall_rule(&mut rules, libc::SYS_clone, newuser);
        add_whole_syscall_rule(&mut rules, libc::SYS_setns);
    }
    Ok(rules)
}

/// A rule matching a `CLONE_NEWUSER`-bearing flags argument. `flags` is arg0
/// for both `unshare(2)` and, on the architectures seccompiler supports
/// (x86-64, aarch64, and riscv64), `clone(2)`. Dword: `CLONE_NEWUSER` sits in
/// the low 32 bits, and `unshare`'s C prototype takes a 32-bit int whose upper
/// register half is undefined.
fn clone_newuser_rule() -> Result<SeccompRule> {
    let condition = SeccompCondition::new(
        0, // arg0 = flags
        SeccompCmpArgLen::Dword,
        SeccompCmpOp::MaskedEq(libc::CLONE_NEWUSER as u64),
        libc::CLONE_NEWUSER as u64,
    )
    .map_err(|e| Error::confinement("seccomp", e))?;
    SeccompRule::new(vec![condition]).map_err(|e| Error::confinement("seccomp", e))
}

/// Rules mapped to `Errno(ENOSYS)`: whole syscalls whose operations the other
/// filters cannot see, where `ENOSYS` makes runtimes fall back to plain
/// syscalls that they can.
fn enosys_rules(config: &SandboxConfig) -> RuleMap {
    let mut rules = RuleMap::new();
    // io_uring can recreate any denied socket operation, so it stays denied
    // unless both policies sit at their most permissive level.
    if config.network != NetworkPolicy::Full || config.linux_ipc == IpcPolicy::Strict {
        for &syscall in IO_URING_SYSCALLS {
            add_whole_syscall_rule(&mut rules, syscall);
        }
    }
    // clone3's flags live in a struct seccomp cannot dereference; `ENOSYS`
    // sends glibc and other runtimes down their fallback to `clone`, whose
    // flags the EPERM filter inspects.
    if config.linux_user_namespaces == UserNamespacePolicy::Deny {
        add_whole_syscall_rule(&mut rules, libc::SYS_clone3);
    }
    rules
}

/// Unix socket creation denials under `IpcPolicy::Strict`. Kept out of the
/// Trap filter so tools probing optional local sockets get a graceful errno.
fn unix_socket_rules() -> Result<RuleMap> {
    let mut rules = RuleMap::new();
    add_syscall_rule(
        &mut rules,
        libc::SYS_socket,
        socket_domain_rule(libc::AF_UNIX)?,
    );
    add_syscall_rule(
        &mut rules,
        libc::SYS_socketpair,
        unix_datagram_socketpair_rule()?,
    );
    Ok(rules)
}

/// A rule matching `socketpair(AF_UNIX, SOCK_DGRAM | flags, ..)`. Unlike
/// connection-oriented pairs, Unix datagram endpoints can be redirected to
/// pathname or abstract sockets outside the sandbox.
fn unix_datagram_socketpair_rule() -> Result<SeccompRule> {
    let conditions = vec![
        SeccompCondition::new(
            0, // arg0 = domain
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Eq,
            libc::AF_UNIX as u64,
        )
        .map_err(|e| Error::confinement("seccomp", e))?,
        SeccompCondition::new(
            1, // arg1 = type
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::MaskedEq(SOCKET_TYPE_MASK),
            libc::SOCK_DGRAM as u64,
        )
        .map_err(|e| Error::confinement("seccomp", e))?,
    ];
    SeccompRule::new(conditions).map_err(|e| Error::confinement("seccomp", e))
}

/// Compile `rules` into a BPF program mapping matches to `action`; everything
/// else stays allowed.
fn compile(rules: RuleMap, action: SeccompAction) -> Result<BpfProgram> {
    let arch = std::env::consts::ARCH
        .try_into()
        .map_err(|e| Error::confinement("seccomp", e))?;
    let filter = SeccompFilter::new(rules, SeccompAction::Allow, action, arch)
        .map_err(|e| Error::confinement("seccomp", e))?;
    let program: BpfProgram = filter
        .try_into()
        .map_err(|e| Error::confinement("seccomp", e))?;
    Ok(program)
}

/// Install `programs` on the current thread. Called inside `pre_exec` in the
/// freshly forked child: `apply_filter` only issues a `prctl(2)` and a
/// `seccomp(2)` over the parent-built program, and errors are reduced to
/// their raw errno so the child never allocates, formats, or takes a lock.
/// Requires NO_NEW_PRIVS (set earlier in pre_exec).
pub(crate) fn apply(programs: &[BpfProgram]) -> std::io::Result<()> {
    for program in programs {
        seccompiler::apply_filter(program).map_err(|err| match err {
            // Errno-carrying variants pass their existing io::Error through
            // unchanged; it already holds a raw OS code and owns no heap.
            seccompiler::Error::Prctl(e) | seccompiler::Error::Seccomp(e) => e,
            // The remaining variants (empty filter, TSYNC) cannot occur for
            // the programs `build` produces and the flags `apply_filter`
            // passes; map them to a plain errno without formatting anything.
            _ => std::io::Error::from_raw_os_error(libc::EINVAL),
        })?;
    }
    Ok(())
}

fn add_network_rules(rules: &mut RuleMap, policy: NetworkPolicy) -> Result<()> {
    match policy {
        NetworkPolicy::Deny => {
            // Block every non-Unix family, including families added by future
            // kernels. AF_UNIX itself is IpcPolicy's decision (see `build`).
            add_syscall_rule(
                rules,
                libc::SYS_socket,
                socket_domain_allowlist_rule(&[libc::AF_UNIX])?,
            );
        }
        NetworkPolicy::OutboundOnly => {
            // IP sockets pass this filter and AF_UNIX is IpcPolicy's decision
            // (see `build`); every other family is blocked.
            add_syscall_rule(
                rules,
                libc::SYS_socket,
                socket_domain_allowlist_rule(&[libc::AF_UNIX, libc::AF_INET, libc::AF_INET6])?,
            );
            // Binding/listening remains denied for every socket family.
            add_whole_syscall_rule(rules, libc::SYS_bind);
            add_whole_syscall_rule(rules, libc::SYS_listen);
        }
        NetworkPolicy::Full => {}
    }
    Ok(())
}

fn add_ipc_rules(rules: &mut RuleMap, policy: IpcPolicy) -> Result<()> {
    for &sys in ALWAYS_BLOCKED_IPC {
        add_whole_syscall_rule(rules, sys);
    }
    if policy == IpcPolicy::Strict {
        for &sys in STRICT_ONLY_IPC {
            add_whole_syscall_rule(rules, sys);
        }
    }
    Ok(())
}

fn add_syscall_rule(rules: &mut RuleMap, syscall: i64, rule: SeccompRule) {
    for number in syscall_numbers(syscall) {
        rules.entry(number).or_default().push(rule.clone());
    }
}

fn add_whole_syscall_rule(rules: &mut RuleMap, syscall: i64) {
    // Empty Vec = match regardless of arguments.
    for number in syscall_numbers(syscall) {
        rules.entry(number).or_default();
    }
}

#[cfg(target_arch = "x86_64")]
fn syscall_numbers(syscall: i64) -> impl Iterator<Item = i64> {
    let x32_syscall = match syscall {
        libc::SYS_ptrace => X32_SYS_PTRACE,
        libc::SYS_mq_notify => X32_SYS_MQ_NOTIFY,
        libc::SYS_kexec_load => X32_SYS_KEXEC_LOAD,
        libc::SYS_process_vm_readv => X32_SYS_PROCESS_VM_READV,
        libc::SYS_process_vm_writev => X32_SYS_PROCESS_VM_WRITEV,
        _ => syscall,
    };
    [syscall, x32_syscall | X32_SYSCALL_BIT].into_iter()
}

#[cfg(not(target_arch = "x86_64"))]
fn syscall_numbers(syscall: i64) -> impl Iterator<Item = i64> {
    [syscall].into_iter()
}

/// A rule matching `socket(domain not in allowed_families, ..)`.
fn socket_domain_allowlist_rule(allowed_families: &[libc::c_int]) -> Result<SeccompRule> {
    let mut conditions = Vec::with_capacity(allowed_families.len());
    for &family in allowed_families {
        conditions.push(
            SeccompCondition::new(
                0, // arg0 = domain
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::Ne,
                family as u64,
            )
            .map_err(|e| Error::confinement("seccomp", e))?,
        );
    }
    SeccompRule::new(conditions).map_err(|e| Error::confinement("seccomp", e))
}

/// A rule matching `socket(domain == family, ..)`.
fn socket_domain_rule(family: libc::c_int) -> Result<SeccompRule> {
    let condition = SeccompCondition::new(
        0, // arg0 = domain
        SeccompCmpArgLen::Dword,
        SeccompCmpOp::Eq,
        family as u64,
    )
    .map_err(|e| Error::confinement("seccomp", e))?;
    SeccompRule::new(vec![condition]).map_err(|e| Error::confinement("seccomp", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(
        network: NetworkPolicy,
        ipc: IpcPolicy,
        user_namespaces: UserNamespacePolicy,
    ) -> SandboxConfig {
        SandboxConfig {
            network,
            linux_ipc: ipc,
            linux_user_namespaces: user_namespaces,
            ..SandboxConfig::default()
        }
    }

    #[test]
    fn enosys_rules_cover_every_io_uring_syscall_number() {
        let rules = enosys_rules(&SandboxConfig::default());

        for &syscall in IO_URING_SYSCALLS {
            assert!(rules.contains_key(&syscall));
            #[cfg(target_arch = "x86_64")]
            assert!(rules.contains_key(&(syscall | X32_SYSCALL_BIT)));
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn x32_specific_syscalls_use_their_legacy_numbers() {
        for (native, x32) in [
            (libc::SYS_ptrace, X32_SYS_PTRACE),
            (libc::SYS_mq_notify, X32_SYS_MQ_NOTIFY),
            (libc::SYS_kexec_load, X32_SYS_KEXEC_LOAD),
            (libc::SYS_process_vm_readv, X32_SYS_PROCESS_VM_READV),
            (libc::SYS_process_vm_writev, X32_SYS_PROCESS_VM_WRITEV),
        ] {
            assert_eq!(
                syscall_numbers(native).collect::<Vec<_>>(),
                vec![native, x32 | X32_SYSCALL_BIT]
            );
        }
    }

    #[test]
    fn strict_ipc_selects_the_unix_socket_filter() {
        let expected = compile(
            unix_socket_rules().expect("unix socket rules"),
            SeccompAction::Errno(libc::EAFNOSUPPORT as u32),
        )
        .expect("unix socket filter");

        let strict = build(&SandboxConfig::default()).expect("strict filters");
        assert!(strict.iter().any(|p| program_eq(p, &expected)));

        let relaxed_config = SandboxConfig {
            linux_ipc: IpcPolicy::Relaxed,
            ..SandboxConfig::default()
        };
        let relaxed = build(&relaxed_config).expect("relaxed filters");
        assert!(!relaxed.iter().any(|p| program_eq(p, &expected)));
    }

    #[test]
    fn io_uring_denial_requires_full_network_and_relaxed_ipc() {
        for (network, ipc, denied) in [
            (NetworkPolicy::Deny, IpcPolicy::Strict, true),
            (NetworkPolicy::Deny, IpcPolicy::Relaxed, true),
            (NetworkPolicy::Full, IpcPolicy::Strict, true),
            (NetworkPolicy::Full, IpcPolicy::Relaxed, false),
        ] {
            let rules = enosys_rules(&config(network, ipc, UserNamespacePolicy::Deny));
            assert_eq!(
                rules.contains_key(&libc::SYS_io_uring_setup),
                denied,
                "io_uring denial for network={network:?} ipc={ipc:?}"
            );
        }
    }

    #[test]
    fn kernel_surface_is_trapped_regardless_of_policy() {
        for user_namespaces in [UserNamespacePolicy::Deny, UserNamespacePolicy::Allow] {
            let rules = violation_rules(&config(
                NetworkPolicy::Full,
                IpcPolicy::Relaxed,
                user_namespaces,
            ))
            .expect("violation rules");
            for &sys in KERNEL_SURFACE_SYSCALLS {
                assert!(
                    rules.contains_key(&sys),
                    "syscall {sys} must be trapped under {user_namespaces:?}"
                );
            }
        }
    }

    #[test]
    fn mount_machinery_follows_the_user_namespace_policy() {
        for (user_namespaces, denied) in [
            (UserNamespacePolicy::Deny, true),
            (UserNamespacePolicy::Allow, false),
        ] {
            let rules = violation_rules(&config(
                NetworkPolicy::Deny,
                IpcPolicy::Strict,
                user_namespaces,
            ))
            .expect("violation rules");
            for &sys in MOUNT_SYSCALLS {
                assert_eq!(
                    rules.contains_key(&sys),
                    denied,
                    "syscall {sys} denial under {user_namespaces:?}"
                );
            }
        }
    }

    #[test]
    fn namespace_syscalls_follow_the_user_namespace_policy() {
        let denied = probed_kernel_rules(&SandboxConfig::default()).expect("probed rules");
        assert!(denied.contains_key(&libc::SYS_unshare));
        assert!(denied.contains_key(&libc::SYS_clone));
        assert!(denied.contains_key(&libc::SYS_setns));
        // The flags-bearing rules must match on CLONE_NEWUSER, not the whole
        // syscall: plain fork/thread clones stay allowed.
        assert!(!denied[&libc::SYS_unshare].is_empty());
        assert!(!denied[&libc::SYS_clone].is_empty());
        assert!(enosys_rules(&SandboxConfig::default()).contains_key(&libc::SYS_clone3));

        let allowed = probed_kernel_rules(&config(
            NetworkPolicy::Deny,
            IpcPolicy::Strict,
            UserNamespacePolicy::Allow,
        ))
        .expect("probed rules");
        for sys in [libc::SYS_unshare, libc::SYS_clone, libc::SYS_setns] {
            assert!(!allowed.contains_key(&sys));
        }
        for &sys in PROBED_KERNEL_SYSCALLS {
            assert!(
                allowed.contains_key(&sys),
                "probed denial must stay unconditional"
            );
        }
        let enosys = enosys_rules(&config(
            NetworkPolicy::Deny,
            IpcPolicy::Strict,
            UserNamespacePolicy::Allow,
        ));
        assert!(!enosys.contains_key(&libc::SYS_clone3));
    }

    #[test]
    fn most_permissive_config_still_installs_the_unconditional_filters() {
        let programs = build(&config(
            NetworkPolicy::Full,
            IpcPolicy::Relaxed,
            UserNamespacePolicy::Allow,
        ))
        .expect("filters");
        // Trap (ptrace + kernel surface) and EPERM (bpf/perf/userfaultfd)
        // remain; the unix-socket and ENOSYS filters have nothing to deny.
        assert_eq!(programs.len(), 2);
    }

    fn program_eq(actual: &BpfProgram, expected: &BpfProgram) -> bool {
        actual.len() == expected.len()
            && actual
                .iter()
                .zip(expected)
                .all(|(a, e)| (a.code, a.jt, a.jf, a.k) == (e.code, e.jt, e.jf, e.k))
    }
}
