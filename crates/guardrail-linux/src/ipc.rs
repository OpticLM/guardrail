//! Landlock IPC-domain isolation selected by the running kernel ABI.
//!
//! The `landlock` crate currently exposes UAPI through ABI v7. Scopes are
//! therefore expressed with their stable raw UAPI too, alongside ABI v9's
//! `LANDLOCK_ACCESS_FS_RESOLVE_UNIX` right. This keeps the runtime ABI query
//! exact instead of letting the crate cap newer kernels at v7.

use std::mem::size_of;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};

use guardrail_core::{Error, Result, SandboxConfig};
use landlock::PathFd;

use crate::fs::PreparedRuleset;

// Stable values from include/uapi/linux/landlock.h.
const LANDLOCK_CREATE_RULESET_VERSION: libc::c_uint = 1 << 0;
const LANDLOCK_RULE_PATH_BENEATH: libc::c_uint = 1;
const LANDLOCK_ACCESS_FS_REFER: u64 = 1 << 13;
const LANDLOCK_ACCESS_FS_RESOLVE_UNIX: u64 = 1 << 16;
const LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET: u64 = 1 << 0;
const LANDLOCK_SCOPE_SIGNAL: u64 = 1 << 1;

#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
    scoped: u64,
}

#[repr(C, packed)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: libc::c_int,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AbiFeatures {
    scope_abstract_unix_socket: bool,
    scope_signal: bool,
    resolve_pathname_unix_socket: bool,
}

const fn features_for_abi(abi: i32) -> AbiFeatures {
    AbiFeatures {
        scope_abstract_unix_socket: abi >= 6,
        scope_signal: abi >= 6,
        resolve_pathname_unix_socket: abi >= 9,
    }
}

/// Runtime-selected IPC policy. Paths are retained only when ABI v9 can
/// enforce them, so older kernels never validate or open ignored grants.
#[derive(Debug)]
pub(crate) struct Policy {
    abi: i32,
    unix_sockets: Vec<PathBuf>,
}

impl Policy {
    pub(crate) fn new(config: &SandboxConfig) -> Result<Self> {
        let abi = query_abi()?;
        Ok(Self::with_abi(abi, &config.linux_unix_sockets))
    }

    fn with_abi(abi: i32, unix_sockets: &[PathBuf]) -> Self {
        let unix_sockets = if features_for_abi(abi).resolve_pathname_unix_socket {
            unix_sockets.to_vec()
        } else {
            Vec::new()
        };
        Self { abi, unix_sockets }
    }

    /// Build a per-spawn ruleset in the parent. ABI v2-v5 need no IPC
    /// ruleset; ABI v6-v8 scope abstract sockets and signals; ABI v9+ also
    /// handles pathname socket resolution and installs explicit grants.
    pub(crate) fn prepare(&self) -> Result<Option<PreparedRuleset>> {
        let features = features_for_abi(self.abi);
        if !features.scope_abstract_unix_socket {
            return Ok(None);
        }

        let attr = LandlockRulesetAttr {
            // REFER is historical: every Landlock layer denies it by default,
            // even if omitted here. Handle and grant it at `/` below so this
            // IPC-only layer does not narrow the existing filesystem policy.
            handled_access_fs: LANDLOCK_ACCESS_FS_REFER
                | if features.resolve_pathname_unix_socket {
                    LANDLOCK_ACCESS_FS_RESOLVE_UNIX
                } else {
                    0
                },
            handled_access_net: 0,
            scoped: LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | LANDLOCK_SCOPE_SIGNAL,
        };
        // SAFETY: attr has the stable three-u64 UAPI prefix used since ABI v6;
        // later kernels accept this shorter structure with later fields zero.
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
                "landlock IPC",
                std::io::Error::last_os_error(),
            ));
        }
        // SAFETY: a successful landlock_create_ruleset returns a new owned fd.
        let fd = unsafe { OwnedFd::from_raw_fd(fd as libc::c_int) };

        add_path_grant(&fd, Path::new("/"), LANDLOCK_ACCESS_FS_REFER)?;
        for path in &self.unix_sockets {
            add_path_grant(&fd, path, LANDLOCK_ACCESS_FS_RESOLVE_UNIX)?;
        }

        Ok(Some(PreparedRuleset::new(fd)))
    }
}

pub(crate) fn query_abi() -> Result<i32> {
    // SAFETY: VERSION requires a null attribute and zero size and changes no
    // process state.
    let abi = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<LandlockRulesetAttr>(),
            0,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if abi < 0 {
        return Err(Error::confinement(
            "landlock IPC ABI query",
            std::io::Error::last_os_error(),
        ));
    }
    Ok(abi as i32)
}

fn add_path_grant(ruleset_fd: &OwnedFd, path: &Path, allowed_access: u64) -> Result<()> {
    let path_fd = PathFd::new(path).map_err(|e| Error::confinement("landlock IPC path", e))?;
    let attr = LandlockPathBeneathAttr {
        allowed_access,
        parent_fd: path_fd.as_fd().as_raw_fd(),
    };
    // SAFETY: both descriptors are live, attr has the packed UAPI layout, and
    // flags must be zero for ABI v9 path-beneath grants.
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
            "landlock IPC path",
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
        for abi in [2, 5] {
            assert_eq!(
                features_for_abi(abi),
                AbiFeatures {
                    scope_abstract_unix_socket: false,
                    scope_signal: false,
                    resolve_pathname_unix_socket: false,
                }
            );
        }
        for abi in [6, 7, 8] {
            assert_eq!(
                features_for_abi(abi),
                AbiFeatures {
                    scope_abstract_unix_socket: true,
                    scope_signal: true,
                    resolve_pathname_unix_socket: false,
                }
            );
        }
        for abi in [9, 10, 99] {
            assert_eq!(
                features_for_abi(abi),
                AbiFeatures {
                    scope_abstract_unix_socket: true,
                    scope_signal: true,
                    resolve_pathname_unix_socket: true,
                }
            );
        }
    }

    #[test]
    fn pathname_grants_are_discarded_before_abi_v9() {
        let missing = PathBuf::from("/definitely/missing/guardrail.sock");
        assert!(
            Policy::with_abi(8, std::slice::from_ref(&missing))
                .unix_sockets
                .is_empty()
        );
        assert_eq!(
            Policy::with_abi(9, std::slice::from_ref(&missing)).unix_sockets,
            vec![missing]
        );
    }
}
