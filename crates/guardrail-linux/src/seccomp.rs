//! Network and IPC confinement via seccomp-BPF denylists.
//!
//! Default action is Allow (arbitrary shell tools must keep working); specific
//! syscalls/arguments are mapped to `VIOLATION_ACTION`. Trap is used so a
//! violation terminates the child with SIGSYS, which the parent can observe.
//! Network rules live here; IPC rules are added to the same filter via
//! `add_ipc_rules`.
//!
//! Two more filters are stacked as needed; the kernel runs every installed
//! filter and applies the highest-precedence action (Trap > Errno > Allow):
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
//!   io_uring available would bypass the socket rules above. With `ENOSYS` —
//!   not Trap — runtimes that probe io_uring for file I/O (libuv/Node,
//!   tokio-uring) see a kernel without io_uring and fall back to plain
//!   syscalls, which the other filters do govern.

use std::collections::BTreeMap;
use std::convert::TryInto;

use guardrail_core::{Error, IpcPolicy, NetworkPolicy, Result, SandboxConfig};
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
const X32_SYS_PROCESS_VM_READV: i64 = 539;
#[cfg(target_arch = "x86_64")]
const X32_SYS_PROCESS_VM_WRITEV: i64 = 540;

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

/// Build the seccomp filters for `config`. Returns an empty Vec when no rules
/// apply, meaning the caller should skip installation.
pub(crate) fn build(config: &SandboxConfig) -> Result<Vec<BpfProgram>> {
    let mut programs = Vec::new();

    let mut violations: RuleMap = BTreeMap::new();
    add_network_rules(&mut violations, config.network)?;
    add_ipc_rules(&mut violations, config.ipc)?;
    if !violations.is_empty() {
        programs.push(compile(violations, VIOLATION_ACTION)?);
    }

    if config.ipc == IpcPolicy::Strict {
        programs.push(compile(
            unix_socket_rules()?,
            SeccompAction::Errno(libc::EAFNOSUPPORT as u32),
        )?);
    }

    // io_uring can recreate any denied socket operation, so it stays denied
    // unless both policies sit at their most permissive level.
    if config.network != NetworkPolicy::Full || config.ipc == IpcPolicy::Strict {
        programs.push(compile(
            io_uring_rules(),
            SeccompAction::Errno(libc::ENOSYS as u32),
        )?);
    }

    Ok(programs)
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

fn io_uring_rules() -> RuleMap {
    let mut rules = RuleMap::new();
    for &syscall in IO_URING_SYSCALLS {
        add_whole_syscall_rule(&mut rules, syscall);
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

/// Install `programs` on the current thread. Requires NO_NEW_PRIVS (set
/// earlier in pre_exec). Async-signal-safe enough for pre_exec (prctl
/// wrappers).
pub(crate) fn apply(programs: &[BpfProgram]) -> Result<()> {
    for program in programs {
        seccompiler::apply_filter(program).map_err(|e| Error::confinement("seccomp", e))?;
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

    #[test]
    fn io_uring_rules_cover_every_syscall_number() {
        let rules = io_uring_rules();

        for &syscall in IO_URING_SYSCALLS {
            assert!(rules.contains_key(&syscall));
            #[cfg(target_arch = "x86_64")]
            assert!(rules.contains_key(&(syscall | X32_SYSCALL_BIT)));
        }

        #[cfg(target_arch = "x86_64")]
        assert_eq!(rules.len(), IO_URING_SYSCALLS.len() * 2);
        #[cfg(not(target_arch = "x86_64"))]
        assert_eq!(rules.len(), IO_URING_SYSCALLS.len());
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn x32_specific_syscalls_use_their_legacy_numbers() {
        for (native, x32) in [
            (libc::SYS_ptrace, X32_SYS_PTRACE),
            (libc::SYS_mq_notify, X32_SYS_MQ_NOTIFY),
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
            ipc: IpcPolicy::Relaxed,
            ..SandboxConfig::default()
        };
        let relaxed = build(&relaxed_config).expect("relaxed filters");
        assert!(!relaxed.iter().any(|p| program_eq(p, &expected)));
    }

    #[test]
    fn io_uring_filter_requires_full_network_and_relaxed_ipc() {
        let expected = compile(io_uring_rules(), SeccompAction::Errno(libc::ENOSYS as u32))
            .expect("io_uring filter");

        for (network, ipc, denied) in [
            (NetworkPolicy::Deny, IpcPolicy::Strict, true),
            (NetworkPolicy::Deny, IpcPolicy::Relaxed, true),
            (NetworkPolicy::Full, IpcPolicy::Strict, true),
            (NetworkPolicy::Full, IpcPolicy::Relaxed, false),
        ] {
            let config = SandboxConfig {
                network,
                ipc,
                ..SandboxConfig::default()
            };
            let programs = build(&config).expect("filters");
            assert_eq!(
                programs.iter().any(|p| program_eq(p, &expected)),
                denied,
                "io_uring filter presence for network={network:?} ipc={ipc:?}"
            );
        }
    }

    fn program_eq(actual: &BpfProgram, expected: &BpfProgram) -> bool {
        actual.len() == expected.len()
            && actual
                .iter()
                .zip(expected)
                .all(|(a, e)| (a.code, a.jt, a.jf, a.k) == (e.code, e.jt, e.jf, e.k))
    }
}
