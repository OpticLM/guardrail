//! Network and IPC confinement via a seccomp-BPF denylist.
//!
//! Default action is Allow (arbitrary shell tools must keep working); specific
//! syscalls/arguments are mapped to `VIOLATION_ACTION`. Trap is used so a
//! violation terminates the child with SIGSYS, which the parent can observe.
//! Network rules live here; IPC rules are added the same filter via `add_ipc_rules`.

use std::collections::BTreeMap;
use std::convert::TryInto;

use guardrail_core::{Error, IpcPolicy, NetworkPolicy, SandboxConfig};
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule,
};

/// Action taken when a denied syscall is attempted. Trap -> SIGSYS (observable
/// by the parent). Change to `SeccompAction::Errno(libc::EACCES as u32)` for
/// graceful per-call failure instead of process termination.
const VIOLATION_ACTION: SeccompAction = SeccompAction::Trap;

type RuleMap = BTreeMap<i64, Vec<SeccompRule>>;

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

/// Build the combined seccomp filter for `config`. Returns `Ok(None)` when no
/// rules apply, meaning the caller should skip installation.
pub(crate) fn build(config: &SandboxConfig) -> Result<Option<BpfProgram>, Error> {
    let mut rules: RuleMap = BTreeMap::new();
    add_network_rules(&mut rules, config.network)?;
    add_ipc_rules(&mut rules, config.ipc)?;

    if rules.is_empty() {
        return Ok(None);
    }

    let arch = std::env::consts::ARCH
        .try_into()
        .map_err(|e| Error::confinement("seccomp", e))?;
    let filter = SeccompFilter::new(rules, SeccompAction::Allow, VIOLATION_ACTION, arch)
        .map_err(|e| Error::confinement("seccomp", e))?;
    let program: BpfProgram = filter
        .try_into()
        .map_err(|e| Error::confinement("seccomp", e))?;
    Ok(Some(program))
}

/// Install `program` on the current thread. Requires NO_NEW_PRIVS (set earlier
/// in pre_exec). Async-signal-safe enough for pre_exec (a prctl wrapper).
pub(crate) fn apply(program: &BpfProgram) -> Result<(), Error> {
    seccompiler::apply_filter(program).map_err(|e| Error::confinement("seccomp", e))
}

fn add_network_rules(rules: &mut RuleMap, policy: NetworkPolicy) -> Result<(), Error> {
    match policy {
        NetworkPolicy::Deny => {
            // Block creation of IP sockets at the source.
            rules
                .entry(libc::SYS_socket)
                .or_default()
                .push(socket_domain_rule(libc::AF_INET)?);
            rules
                .entry(libc::SYS_socket)
                .or_default()
                .push(socket_domain_rule(libc::AF_INET6)?);
        }
        NetworkPolicy::OutboundOnly => {
            // IP sockets allowed; binding/listening denied (any args).
            rules.entry(libc::SYS_bind).or_default();
            rules.entry(libc::SYS_listen).or_default();
        }
        NetworkPolicy::Full => {}
    }
    Ok(())
}

fn add_ipc_rules(rules: &mut RuleMap, policy: IpcPolicy) -> Result<(), Error> {
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

fn add_whole_syscall_rule(rules: &mut RuleMap, syscall: i64) {
    // Empty Vec = match regardless of arguments.
    rules.entry(syscall).or_default();
}

/// A rule matching `socket(domain == family, ..)`.
fn socket_domain_rule(family: libc::c_int) -> Result<SeccompRule, Error> {
    let cond = SeccompCondition::new(
        0, // arg0 = domain
        SeccompCmpArgLen::Dword,
        SeccompCmpOp::Eq,
        family as u64,
    )
    .map_err(|e| Error::confinement("seccomp", e))?;
    SeccompRule::new(vec![cond]).map_err(|e| Error::confinement("seccomp", e))
}
