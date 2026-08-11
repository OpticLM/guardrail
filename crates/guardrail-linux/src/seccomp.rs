//! Network and kernel-attack-surface confinement via seccomp-BPF denylists.
//!
//! Default action is Allow (arbitrary shell tools must keep working); the
//! stacked filters below deny specific syscalls/arguments. The kernel runs
//! every installed filter and applies the highest-precedence action
//! (Trap > Errno > Allow):
//!
//! * Kernel-interface syscalls no shell tool legitimately calls — kernel code
//!   loading, the keyring, host-state interference, and, under
//!   `UserNamespacePolicy::Deny`, the mount machinery — are mapped to
//!   `VIOLATION_ACTION`. Trap is used so a violation terminates the child
//!   with SIGSYS, which the parent can observe.
//!
//! * Creating a socket of a family outside the network policy's allowlist
//!   fails with `EAFNOSUPPORT` — the errno of a kernel built without that
//!   family, which every network runtime's probe-and-fall-back path already
//!   handles. A trap would turn routine libc behavior into a kill: glibc's
//!   `getaddrinfo` opens an `AF_NETLINK` route socket to enumerate local
//!   addresses, so every DNS lookup through libc would die with SIGSYS under
//!   `Deny` and `OutboundOnly`.
//!
//! * Kernel interfaces that legitimate tooling probes and must fall back from
//!   gracefully — `bpf`, `perf_event_open`, `userfaultfd`, plus namespace
//!   creation/joining under `UserNamespacePolicy::Deny` — fail with `EPERM`,
//!   the same errno an unprivileged caller sees from a hardened kernel.
//!
//! * io_uring is denied with `ENOSYS` unless the network policy is `Full`:
//!   ring-submitted operations (`IORING_OP_SOCKET`,
//!   `IORING_OP_CONNECT`, `IORING_OP_BIND`, ...) are not syscalls, so leaving
//!   io_uring available would bypass the socket rules. With `ENOSYS` — not
//!   Trap — runtimes that probe io_uring for file I/O (libuv/Node,
//!   tokio-uring) see a kernel without io_uring and fall back to plain
//!   syscalls, which the other filters do govern. `clone3` joins this filter
//!   under `UserNamespacePolicy::Deny`: its flags live in a struct seccomp
//!   cannot read, and `ENOSYS` makes glibc and other runtimes fall back to
//!   plain `clone`, whose flags the `EPERM` filter can inspect.
//!
//! seccomp cannot see a socket fd's family, so under `OutboundOnly` the
//! family-aware TCP and UDP bind restrictions live in the Landlock network
//! layer (see `crate::net`).

use std::collections::BTreeMap;
use std::convert::TryInto;

use guardrail_core::{Error, NetworkPolicy, Result, SandboxConfig, UserNamespacePolicy};
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule,
};

/// Action taken when a kernel-attack-surface syscall is attempted. Trap ->
/// SIGSYS (observable by the parent). Change to
/// `SeccompAction::Errno(libc::EACCES as u32)` for graceful per-call failure
/// instead of process termination.
const VIOLATION_ACTION: SeccompAction = SeccompAction::Trap;

type RuleMap = BTreeMap<i64, Vec<SeccompRule>>;

/// x32 uses the x86-64 audit architecture but sets bit 30 in the syscall
/// number. Seccomp rules must therefore cover both ABIs on x86-64.
#[cfg(target_arch = "x86_64")]
const X32_SYSCALL_BIT: i64 = 0x4000_0000;

// Legacy x32 entries whose base numbers differ from native x86-64.
#[cfg(target_arch = "x86_64")]
const X32_SYS_KEXEC_LOAD: i64 = 528;

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

/// io_uring syscalls, denied with `ENOSYS` unless the network policy is
/// `Full`. Operations submitted through a ring never pass the syscall filter,
/// so the socket-family rules cannot see them. `enter` and `register` are
/// included besides `setup` so an inherited or fd-passed ring is equally
/// unusable.
const IO_URING_SYSCALLS: &[i64] = &[
    libc::SYS_io_uring_setup,
    libc::SYS_io_uring_enter,
    libc::SYS_io_uring_register,
];

/// Build the seccomp filters for `config`.
pub(crate) fn build(config: &SandboxConfig) -> Result<Vec<BpfProgram>> {
    let mut programs = Vec::new();

    programs.push(compile(violation_rules(config), VIOLATION_ACTION)?);

    let network = network_rules(config.network)?;
    if !network.is_empty() {
        programs.push(compile(
            network,
            SeccompAction::Errno(libc::EAFNOSUPPORT as u32),
        )?);
    }

    programs.push(compile(
        probed_kernel_rules(config)?,
        SeccompAction::Errno(libc::EPERM as u32),
    )?);

    let enosys = enosys_rules(config);
    if !enosys.is_empty() {
        programs.push(compile(enosys, SeccompAction::Errno(libc::ENOSYS as u32))?);
    }

    Ok(programs)
}

/// Rules mapped to `VIOLATION_ACTION`: the kernel-attack-surface denylist.
fn violation_rules(config: &SandboxConfig) -> RuleMap {
    let mut rules = RuleMap::new();
    add_kernel_surface_rules(&mut rules, config.linux_user_namespaces);
    rules
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
    // unless the network policy is fully open.
    if config.network != NetworkPolicy::Full {
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

/// Rules mapped to `Errno(EAFNOSUPPORT)`: socket creation outside the network
/// policy's family allowlist. The graceful errno keeps probing runtimes alive
/// (glibc `getaddrinfo`'s netlink interface scan, IPv6 availability probes)
/// while still refusing the socket.
fn network_rules(policy: NetworkPolicy) -> Result<RuleMap> {
    let mut rules = RuleMap::new();
    match policy {
        NetworkPolicy::Deny => {
            // Block every non-Unix family, including families added by future
            // kernels. AF_UNIX is host-local IPC, not network reach.
            add_syscall_rule(
                &mut rules,
                libc::SYS_socket,
                socket_domain_allowlist_rule(&[libc::AF_UNIX])?,
            );
        }
        NetworkPolicy::OutboundOnly => {
            // IP and Unix sockets pass this filter; every other family is
            // blocked.
            add_syscall_rule(
                &mut rules,
                libc::SYS_socket,
                socket_domain_allowlist_rule(&[libc::AF_UNIX, libc::AF_INET, libc::AF_INET6])?,
            );
            // Family-aware bind restrictions are applied by Landlock (see
            // `crate::net`); bind/listen must stay available for AF_UNIX.
        }
        NetworkPolicy::Full => {}
    }
    Ok(rules)
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
        libc::SYS_kexec_load => X32_SYS_KEXEC_LOAD,
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
                domain_as_u64(family),
            )
            .map_err(|e| Error::confinement("seccomp", e))?,
        );
    }
    SeccompRule::new(conditions).map_err(|e| Error::confinement("seccomp", e))
}

/// Widen a socket domain (`AF_*` constant, always non-negative) to the `u64`
/// seccomp compares against. `try_from` rejects a negative value rather than
/// silently reinterpreting the sign bit as `as` would.
fn domain_as_u64(family: libc::c_int) -> u64 {
    u64::try_from(family).expect("socket domain constant is non-negative")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(network: NetworkPolicy, user_namespaces: UserNamespacePolicy) -> SandboxConfig {
        SandboxConfig {
            network,
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
        assert_eq!(
            syscall_numbers(libc::SYS_kexec_load).collect::<Vec<_>>(),
            vec![libc::SYS_kexec_load, X32_SYS_KEXEC_LOAD | X32_SYSCALL_BIT]
        );
    }

    #[test]
    fn io_uring_denial_follows_network_policy() {
        for (network, denied) in [
            (NetworkPolicy::Deny, true),
            (NetworkPolicy::OutboundOnly, true),
            (NetworkPolicy::Full, false),
        ] {
            let rules = enosys_rules(&config(network, UserNamespacePolicy::Deny));
            assert_eq!(
                rules.contains_key(&libc::SYS_io_uring_setup),
                denied,
                "io_uring denial for network={network:?}"
            );
        }
    }

    #[test]
    fn socket_family_denial_follows_network_policy() {
        for (network, denied) in [
            (NetworkPolicy::Deny, true),
            (NetworkPolicy::OutboundOnly, true),
            (NetworkPolicy::Full, false),
        ] {
            let rules = network_rules(network).expect("network rules");
            assert_eq!(
                rules.contains_key(&libc::SYS_socket),
                denied,
                "socket family rule for network={network:?}"
            );
        }
    }

    #[test]
    fn outbound_only_never_denies_family_blind_bind_listen() {
        let rules = network_rules(NetworkPolicy::OutboundOnly).expect("network rules");
        for sys in [libc::SYS_bind, libc::SYS_listen] {
            assert!(
                !rules.contains_key(&sys),
                "syscall {sys} denied under OutboundOnly"
            );
        }
    }

    #[test]
    fn kernel_surface_is_trapped_regardless_of_policy() {
        for user_namespaces in [UserNamespacePolicy::Deny, UserNamespacePolicy::Allow] {
            let rules = violation_rules(&config(NetworkPolicy::Full, user_namespaces));
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
            let rules = violation_rules(&config(NetworkPolicy::Deny, user_namespaces));
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

        let allowed = probed_kernel_rules(&config(NetworkPolicy::Deny, UserNamespacePolicy::Allow))
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
        let enosys = enosys_rules(&config(NetworkPolicy::Deny, UserNamespacePolicy::Allow));
        assert!(!enosys.contains_key(&libc::SYS_clone3));
    }

    #[test]
    fn most_permissive_config_still_installs_the_unconditional_filters() {
        let programs =
            build(&config(NetworkPolicy::Full, UserNamespacePolicy::Allow)).expect("filters");
        // Trap (kernel surface) and EPERM (bpf/perf/userfaultfd) remain; the
        // EAFNOSUPPORT and ENOSYS filters have nothing to deny.
        assert_eq!(programs.len(), 2);
    }
}
