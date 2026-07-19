//! Family-aware network confinement via the Landlock network LSM (ABI v4,
//! Linux 6.7+).
//!
//! seccomp cannot see a socket fd's family at `bind`/`listen` time, so under
//! `NetworkPolicy::OutboundOnly` the family-blind seccomp traps would also
//! kill the Unix-domain servers that `IpcPolicy::Relaxed` permits. For that
//! policy combination the explicit TCP-bind denial moves here: a Landlock
//! ruleset handling `AccessNet::BindTcp` with no rules denies binding a TCP
//! socket to any port (`EACCES`), while outbound `connect` stays unrestricted
//! because `ConnectTcp` is not handled. Fails closed: on kernels without
//! Landlock ABI v4 the backend refuses to construct instead of running the
//! child with the contract silently narrowed.
//!
//! Known residuals of what the kernel can express today, documented in the
//! crate docs: `listen(2)` on an unbound TCP socket autobinds an ephemeral
//! port without passing the LSM bind hook, and UDP bind is not yet covered
//! (Landlock gained UDP rights in ABI v10, which the `landlock` crate does
//! not expose yet). `IpcPolicy::Strict` keeps the stricter whole-syscall
//! seccomp traps instead.

use std::os::fd::OwnedFd;

use landlock::{AccessNet, CompatLevel, Compatible, Ruleset, RulesetAttr};

use guardrail_core::{Error, IpcPolicy, NetworkPolicy, Result, SandboxConfig};

use crate::fs::PreparedRuleset;

/// Build the Landlock network ruleset for `config`, entirely in the parent:
/// `Some` ruleset denying all TCP bind when `OutboundOnly` composes with
/// `Relaxed` IPC, `None` when the seccomp filters already cover the policy.
pub(crate) fn prepare(config: &SandboxConfig) -> Result<Option<PreparedRuleset>> {
    if config.network != NetworkPolicy::OutboundOnly || config.linux_ipc != IpcPolicy::Relaxed {
        return Ok(None);
    }

    let ruleset = Ruleset::default()
        // Error out instead of silently skipping the denial when the kernel
        // predates Landlock ABI v4 (Linux 6.7).
        .set_compatibility(CompatLevel::HardRequirement)
        // Handling BindTcp with no rules denies TCP bind on every port;
        // ConnectTcp is left unhandled so outbound connections are untouched.
        .handle_access(AccessNet::BindTcp)
        .map_err(unsupported)?
        .create()
        .map_err(unsupported)?;

    let fd = Option::<OwnedFd>::from(ruleset).ok_or_else(|| {
        Error::Unsupported(
            "Landlock network ruleset is not enforced on this kernel; refusing \
             to run the child without the OutboundOnly TCP-bind denial"
                .into(),
        )
    })?;
    Ok(Some(PreparedRuleset::new(fd)))
}

fn unsupported(err: landlock::RulesetError) -> Error {
    Error::Unsupported(format!(
        "NetworkPolicy::OutboundOnly with IpcPolicy::Relaxed requires Landlock \
         network support (ABI v4, Linux 6.7+) to deny TCP bind while \
         permitting Unix-domain ones: {err}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(network: NetworkPolicy, ipc: IpcPolicy) -> SandboxConfig {
        SandboxConfig {
            network,
            linux_ipc: ipc,
            ..SandboxConfig::default()
        }
    }

    #[test]
    fn only_outbound_only_with_relaxed_ipc_builds_a_net_ruleset() {
        for (network, ipc, wanted) in [
            (NetworkPolicy::Deny, IpcPolicy::Strict, false),
            (NetworkPolicy::Deny, IpcPolicy::Relaxed, false),
            (NetworkPolicy::OutboundOnly, IpcPolicy::Strict, false),
            (NetworkPolicy::OutboundOnly, IpcPolicy::Relaxed, true),
            (NetworkPolicy::Full, IpcPolicy::Strict, false),
            (NetworkPolicy::Full, IpcPolicy::Relaxed, false),
        ] {
            match prepare(&config(network, ipc)) {
                Ok(ruleset) => assert_eq!(
                    ruleset.is_some(),
                    wanted,
                    "net ruleset for network={network:?} ipc={ipc:?}"
                ),
                Err(Error::Unsupported(reason)) => {
                    assert!(wanted, "unexpected Unsupported for {network:?}/{ipc:?}");
                    eprintln!("skipping: Landlock ABI v4 unavailable: {reason}");
                }
                Err(other) => panic!("unexpected error: {other:?}"),
            }
        }
    }
}
