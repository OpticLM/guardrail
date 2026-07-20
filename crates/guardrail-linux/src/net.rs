//! Family-aware `OutboundOnly` bind confinement via Landlock.
//!
//! seccomp cannot recover a socket's family from its fd at `bind`/`listen`
//! time, so Landlock handles the IP-specific restrictions. ABI v4+ denies
//! every explicit TCP bind by handling `LANDLOCK_ACCESS_NET_BIND_TCP` without
//! granting any port. ABI v10+ also handles UDP bind and grants only port 0,
//! preserving kernel-selected ephemeral binds while denying fixed local
//! ports. UDP bind remains unrestricted on ABI v4-v9.
//!
//! `listen(2)` on an unbound TCP socket implicitly selects an ephemeral port
//! without an explicit `bind(2)` and remains available on every supported ABI.
//! ABI v2-v3 cannot enforce the TCP-bind part of `OutboundOnly`, so backend
//! construction fails closed for that policy.

use std::mem::size_of;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;

use guardrail_core::{Error, NetworkPolicy, Result, SandboxConfig};
use landlock::PathFd;

use crate::fs::PreparedRuleset;
use crate::ipc::query_abi;

// Stable values from include/uapi/linux/landlock.h.
const LANDLOCK_RULE_NET_PORT: libc::c_uint = 2;
const LANDLOCK_RULE_PATH_BENEATH: libc::c_uint = 1;
const LANDLOCK_ACCESS_FS_REFER: u64 = 1 << 13;
const LANDLOCK_ACCESS_NET_BIND_TCP: u64 = 1 << 0;
const LANDLOCK_ACCESS_NET_BIND_UDP: u64 = 1 << 2;

#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
    scoped: u64,
}

#[repr(C)]
struct LandlockNetPortAttr {
    allowed_access: u64,
    port: u64,
}

#[repr(C, packed)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: libc::c_int,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AbiFeatures {
    bind_tcp: bool,
    bind_udp: bool,
}

const fn features_for_abi(abi: i32) -> AbiFeatures {
    AbiFeatures {
        bind_tcp: abi >= 4,
        bind_udp: abi >= 10,
    }
}

/// Build the Landlock network layer for `OutboundOnly` in the parent.
pub(crate) fn prepare(config: &SandboxConfig) -> Result<Option<PreparedRuleset>> {
    if config.network != NetworkPolicy::OutboundOnly {
        return Ok(None);
    }

    let abi = query_abi()?;
    let features = features_for_abi(abi);
    if !features.bind_tcp {
        return Err(Error::Unsupported(format!(
            "NetworkPolicy::OutboundOnly requires Landlock network support \
             (ABI v4+); the running kernel reports ABI v{abi}"
        )));
    }

    let attr = LandlockRulesetAttr {
        // Every Landlock layer implicitly denies REFER, even when it is not
        // listed. Handle it and grant it at `/` below so this network-only
        // layer does not narrow the filesystem policy.
        handled_access_fs: LANDLOCK_ACCESS_FS_REFER,
        handled_access_net: LANDLOCK_ACCESS_NET_BIND_TCP
            | if features.bind_udp {
                LANDLOCK_ACCESS_NET_BIND_UDP
            } else {
                0
            },
        scoped: 0,
    };
    // SAFETY: attr is the stable three-u64 UAPI prefix. ABI v10+ accepts this
    // shorter form and treats its later quiet-access fields as zero.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &attr,
            size_of::<LandlockRulesetAttr>(),
            0 as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(Error::confinement(
            "landlock network",
            std::io::Error::last_os_error(),
        ));
    }
    // SAFETY: a successful landlock_create_ruleset returns a new owned fd.
    let fd = unsafe { OwnedFd::from_raw_fd(fd as libc::c_int) };

    add_path_grant(&fd, Path::new("/"), LANDLOCK_ACCESS_FS_REFER)?;
    if features.bind_udp {
        // A port-0 rule specifically grants kernel-assigned ephemeral UDP
        // binding. Every nonzero local port remains denied by this layer.
        add_port_grant(&fd, LANDLOCK_ACCESS_NET_BIND_UDP, 0)?;
    }

    Ok(Some(PreparedRuleset::new(fd)))
}

fn add_path_grant(ruleset_fd: &OwnedFd, path: &Path, allowed_access: u64) -> Result<()> {
    let path_fd = PathFd::new(path).map_err(|e| Error::confinement("landlock network path", e))?;
    let attr = LandlockPathBeneathAttr {
        allowed_access,
        parent_fd: path_fd.as_fd().as_raw_fd(),
    };
    // SAFETY: both descriptors are live, attr has the packed path-beneath
    // UAPI layout, and flags must be zero.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset_fd.as_raw_fd(),
            LANDLOCK_RULE_PATH_BENEATH,
            &attr,
            0 as libc::c_uint,
        )
    };
    if rc != 0 {
        return Err(Error::confinement(
            "landlock network path",
            std::io::Error::last_os_error(),
        ));
    }
    Ok(())
}

fn add_port_grant(ruleset_fd: &OwnedFd, allowed_access: u64, port: u64) -> Result<()> {
    let attr = LandlockNetPortAttr {
        allowed_access,
        port,
    };
    // SAFETY: ruleset_fd is a live Landlock ruleset descriptor, attr has the
    // stable two-u64 network-port UAPI layout, and flags must be zero.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset_fd.as_raw_fd(),
            LANDLOCK_RULE_NET_PORT,
            &attr,
            0 as libc::c_uint,
        )
    };
    if rc != 0 {
        return Err(Error::confinement(
            "landlock network port",
            std::io::Error::last_os_error(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abi_policy_matrix_is_exact() {
        for abi in [2, 3] {
            assert_eq!(
                features_for_abi(abi),
                AbiFeatures {
                    bind_tcp: false,
                    bind_udp: false,
                }
            );
        }
        for abi in [4, 5, 6, 7, 8, 9] {
            assert_eq!(
                features_for_abi(abi),
                AbiFeatures {
                    bind_tcp: true,
                    bind_udp: false,
                }
            );
        }
        for abi in [10, 11, 99] {
            assert_eq!(
                features_for_abi(abi),
                AbiFeatures {
                    bind_tcp: true,
                    bind_udp: true,
                }
            );
        }
    }
}
