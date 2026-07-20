//! Filesystem confinement via the Landlock LSM plus mount masking.
//!
//! Landlock denies *everything* not explicitly allowed, including loading and
//! executing the target binary and its shared libraries — but its rules are
//! purely additive grants, so a deny rule beneath an allowed parent cannot be
//! expressed as Landlock rules without freezing the directory's contents at
//! compile time. The backend therefore compiles ordered allow/deny rules into
//! two cooperating layers:
//!
//! * the Landlock ruleset grants exactly the allow-rule paths whose final
//!   ordered effect is Allow — wholesale, so entries created at any later
//!   time are covered;
//! * every deny that falls beneath a covering grant becomes a mount mask
//!   (see [`crate::ns`]) glued over the denied path inside a per-spawn user +
//!   mount namespace, which stays faithful to the ordered policy no matter
//!   when files appear on either side.
//!
//! One policy shape has no faithful encoding: denying *read* on a path while
//! write or execute stays allowed there (a hidden path cannot remain
//! writable). Compilation fails with [`Error::Unsupported`] instead of
//! approximating.

use std::collections::BTreeSet;
use std::ffi::CString;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use landlock::{
    ABI, Access, AccessFs, BitFlags, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset,
    RulesetAttr, RulesetCreated, RulesetCreatedAttr, make_bitflags,
};

use guardrail_core::{Error, FsAccess, Result};

use crate::ns;

// Stable Landlock UAPI values through ABI v2. The private `/dev/shm` rule
// allows every V2 read/write/create/remove/refer right, but not Execute.
const LANDLOCK_RULE_PATH_BENEATH: libc::c_uint = 1;
const PRIVATE_SHM_ACCESS_FS: u64 = 0x3ffe;

#[repr(C, packed)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: libc::c_int,
}

#[derive(Debug, PartialEq)]
pub(crate) struct CompiledRules {
    read_paths: BTreeSet<PathBuf>,
    write_paths: BTreeSet<PathBuf>,
    execute_paths: BTreeSet<PathBuf>,
    pub(crate) mount_plan: ns::MountPlan,
}

/// Compile ordered filesystem allow/deny rules into positive Landlock paths
/// and a mount-masking plan for deny-under-allow boundaries.
///
/// This runs in the parent before `fork()`, so policy compilation errors
/// remain structured [`Error::Confinement`] / [`Error::Unsupported`] values
/// instead of being collapsed into a `pre_exec` spawn failure.
pub(crate) fn compile(rules: &[FsAccess]) -> Result<CompiledRules> {
    let normalized = normalize_rules(rules)?;
    let read_paths = allow_roots(&normalized, FsRight::Read);
    let write_paths = allow_roots(&normalized, FsRight::Write);
    let execute_paths = allow_roots(&normalized, FsRight::Execute);
    let mount_plan = plan_masks(&normalized, &read_paths, &write_paths, &execute_paths)?;
    Ok(CompiledRules {
        read_paths,
        write_paths,
        execute_paths,
        mount_plan,
    })
}

/// A Landlock ruleset built in the parent with all host-path rules. The child
/// adds only its newly mounted private `/dev/shm` before enforcement.
#[derive(Debug)]
pub(crate) struct PreparedRuleset {
    fd: OwnedFd,
}

impl PreparedRuleset {
    pub(crate) fn new(fd: OwnedFd) -> Self {
        Self { fd }
    }

    /// Duplicate the ruleset descriptor so an owned copy can move into a
    /// per-spawn `pre_exec` closure.
    pub(crate) fn try_clone(&self) -> Result<Self> {
        let fd = self
            .fd
            .try_clone()
            .map_err(|e| Error::confinement("landlock", e))?;
        Ok(Self { fd })
    }

    /// Add the child-private `/dev/shm` hierarchy to this spawn's ruleset.
    /// Called after the tmpfs is mounted but before the ruleset is enforced,
    /// so this rule identifies the private mount rather than the hidden host
    /// `/dev/shm`. Only raw syscalls are used in the post-fork child.
    pub(crate) fn allow_private_shm(&self) -> std::io::Result<()> {
        // SAFETY: path is a NUL-terminated literal and flags are scalar.
        let path_fd = unsafe {
            libc::open(
                c"/dev/shm".as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if path_fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let attr = LandlockPathBeneathAttr {
            allowed_access: PRIVATE_SHM_ACCESS_FS,
            parent_fd: path_fd,
        };
        // SAFETY: the ruleset fd and path fd are live, attr has the packed
        // kernel UAPI layout, and flags must be zero.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_landlock_add_rule,
                self.fd.as_raw_fd(),
                LANDLOCK_RULE_PATH_BENEATH,
                &attr,
                0 as libc::c_uint,
            )
        };
        let result = if rc == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        };
        // SAFETY: path_fd was opened above and is owned here.
        unsafe { libc::close(path_fd) };
        result
    }

    /// Enforce the ruleset on the calling thread. Called inside `pre_exec` in
    /// the freshly forked child: a single raw `landlock_restrict_self(2)` over
    /// the parent-built descriptor, so the child never runs library code that
    /// may allocate or take a lock. Requires `NO_NEW_PRIVS` (set earlier in
    /// `pre_exec`).
    ///
    /// A zero return from the kernel guarantees the ruleset is active, so the
    /// silent `NotEnforced` downgrade the landlock crate can report cannot
    /// happen through this path: the syscall either enforces or errors, and an
    /// error aborts the spawn.
    pub(crate) fn restrict_self(&self) -> std::io::Result<()> {
        // SAFETY: scalar args only; the fd is owned by self and stays open for
        // the duration of the call.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_landlock_restrict_self,
                self.fd.as_raw_fd(),
                0 as libc::c_uint,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

/// Build a Landlock ruleset for compiled host paths in the parent before
/// `fork()`. The child adds its private `/dev/shm` with raw syscalls, then
/// enforces the result with [`PreparedRuleset::restrict_self`]. Building
/// everything else here keeps allocation, host-path opening, and error
/// formatting out of the `pre_exec` closure, which the [`pre_exec` contract]
/// requires under multithreaded parents such as Node.
///
/// Fails closed: on a kernel that cannot enforce Landlock, `handle_access`
/// errors under [`CompatLevel::HardRequirement`] and the spawn is aborted
/// rather than running the child unconfined. `LinuxBackend::new` already
/// refuses to construct a backend on such kernels, so the checks here are
/// defense in depth.
///
/// [`pre_exec` contract]: std::os::unix::process::CommandExt::pre_exec
pub(crate) fn prepare(rules: &CompiledRules) -> Result<PreparedRuleset> {
    // Pin ABI v2 (Linux 5.19+): its `Refer` right is required for write
    // grants to honor cross-directory rename and link, which the portable
    // `WriteAllow` contract promises (issue #24). Kernels without v2 fail the
    // hard requirement below and in `support::probe_required_features` —
    // they are unsupported rather than silently less capable.
    let abi = ABI::V2;

    let mut ruleset = Ruleset::default()
        // Error out instead of the default silent best-effort downgrade when
        // the kernel cannot handle the requested access rights.
        .set_compatibility(CompatLevel::HardRequirement)
        // We mediate ALL filesystem access rights: anything not granted below
        // is denied.
        .handle_access(AccessFs::from_all(abi))
        .map_err(|e| Error::confinement("landlock", e))?
        .create()
        .map_err(|e| Error::confinement("landlock", e))?
        // Per-path rules go back to best-effort: for a non-directory path the
        // crate downgrades the rule to the file-legitimate subset (e.g. drops
        // ReadDir from a file grant). That grants strictly fewer rights, never
        // more, so it cannot fail open — while HardRequirement would reject
        // every rule targeting an individual file.
        .set_compatibility(CompatLevel::BestEffort);

    ruleset = add_path_rules(
        ruleset,
        &rules.read_paths,
        access_for_right(FsRight::Read, abi),
    )?;
    ruleset = add_path_rules(
        ruleset,
        &rules.write_paths,
        access_for_right(FsRight::Write, abi),
    )?;
    ruleset = add_path_rules(
        ruleset,
        &rules.execute_paths,
        access_for_right(FsRight::Execute, abi),
    )?;

    // With every V2 right hard-required above, a created ruleset always
    // carries a real descriptor; `None` means the crate downgraded to a dummy
    // ruleset that would enforce nothing — refuse to run the child.
    let fd = Option::<OwnedFd>::from(ruleset).ok_or_else(|| {
        Error::Unsupported(
            "Landlock ruleset is not enforced on this kernel; refusing to run \
             the child without filesystem confinement"
                .into(),
        )
    })?;
    Ok(PreparedRuleset { fd })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FsRight {
    Read,
    Write,
    Execute,
}

const RIGHTS: [FsRight; 3] = [FsRight::Read, FsRight::Write, FsRight::Execute];

// Rights as a bitset, so a path's combined situation across the three
// independent rights stays one integer.
const READ_BIT: u8 = 0b001;
const WRITE_BIT: u8 = 0b010;
const EXEC_BIT: u8 = 0b100;
const ALL_RIGHTS: u8 = 0b111;

fn right_bit(right: FsRight) -> u8 {
    match right {
        FsRight::Read => READ_BIT,
        FsRight::Write => WRITE_BIT,
        FsRight::Execute => EXEC_BIT,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleEffect {
    Allow,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NormalizedRule {
    right: FsRight,
    effect: RuleEffect,
    path: PathBuf,
}

fn normalize_rules(rules: &[FsAccess]) -> Result<Vec<NormalizedRule>> {
    rules
        .iter()
        .map(|rule| {
            let (right, effect, path) = match rule {
                FsAccess::ReadAllow(path) => (FsRight::Read, RuleEffect::Allow, path),
                FsAccess::ReadDeny(path) => (FsRight::Read, RuleEffect::Deny, path),
                FsAccess::WriteAllow(path) => (FsRight::Write, RuleEffect::Allow, path),
                FsAccess::WriteDeny(path) => (FsRight::Write, RuleEffect::Deny, path),
                FsAccess::ExecuteAllow(path) => (FsRight::Execute, RuleEffect::Allow, path),
                FsAccess::ExecuteDeny(path) => (FsRight::Execute, RuleEffect::Deny, path),
            };
            let path =
                std::fs::canonicalize(path).map_err(|err| Error::confinement("landlock", err))?;
            Ok(NormalizedRule {
                right,
                effect,
                path,
            })
        })
        .collect()
}

fn final_effect(rules: &[NormalizedRule], right: FsRight, path: &Path) -> RuleEffect {
    let mut effect = RuleEffect::Deny;
    for rule in rules {
        if rule.right == right && path.starts_with(&rule.path) {
            effect = rule.effect;
        }
    }
    effect
}

/// The Landlock grants for `right`: every allow-rule path whose final ordered
/// effect is still Allow. Grants are wholesale — deny boundaries beneath them
/// are enforced by mount masks, not by shrinking the grant.
fn allow_roots(rules: &[NormalizedRule], right: FsRight) -> BTreeSet<PathBuf> {
    rules
        .iter()
        .filter(|rule| rule.right == right && rule.effect == RuleEffect::Allow)
        .filter(|rule| final_effect(rules, right, &rule.path) == RuleEffect::Allow)
        .map(|rule| rule.path.clone())
        .collect()
}

/// How a rule path already processed shapes the paths beneath it.
#[derive(Debug)]
enum Special {
    /// Hidden by a tmpfs / empty-file overmount; nothing beneath is visible
    /// unless re-attached.
    Hide,
    /// Re-attached clone: a fresh mount, so masks above no longer apply;
    /// `restricted` holds rights stripped again on top of the clone.
    Exposed { restricted: u8 },
    /// A recursive read-only / noexec self-bind stripping `rights`.
    Restricted { rights: u8 },
}

/// What the mask chain above `path` does to it: whether it is hidden (and by
/// which hide root), and which rights the restricting binds strip.
struct MaskContext {
    hidden: bool,
    hide_root: Option<PathBuf>,
    blocked: u8,
}

fn mask_context(specials: &[(PathBuf, Special)], path: &Path) -> MaskContext {
    let mut blocked = 0;
    // `specials` is in processing order (ancestors first), so reverse
    // iteration visits the nearest ancestor first.
    for (candidate, special) in specials.iter().rev() {
        if candidate.as_path() == path || !path.starts_with(candidate) {
            continue;
        }
        match special {
            Special::Hide => {
                return MaskContext {
                    hidden: true,
                    hide_root: Some(candidate.clone()),
                    blocked,
                };
            }
            Special::Exposed { restricted } => {
                // A fresh clone mount: masks above it are irrelevant.
                return MaskContext {
                    hidden: false,
                    hide_root: None,
                    blocked: blocked | restricted,
                };
            }
            Special::Restricted { rights } => blocked |= rights,
        }
    }
    MaskContext {
        hidden: false,
        hide_root: None,
        blocked,
    }
}

/// Mount operations planned per rule path, before depth-ordering and CString
/// conversion.
#[derive(Debug)]
enum Planned {
    HideDir(PathBuf),
    HideFile(PathBuf),
    SkeletonDir(PathBuf),
    SkeletonFile(PathBuf),
    Attach {
        slot: usize,
        path: PathBuf,
    },
    Restrict {
        path: PathBuf,
        rights: u8,
        recursive: bool,
    },
}

impl Planned {
    fn path(&self) -> &Path {
        match self {
            Planned::HideDir(path)
            | Planned::HideFile(path)
            | Planned::SkeletonDir(path)
            | Planned::SkeletonFile(path)
            | Planned::Attach { path, .. }
            | Planned::Restrict { path, .. } => path,
        }
    }

    /// Ordering among operations at the same depth and path: masks first,
    /// then the skeleton they contain, then attachments, then restrictions
    /// layered on top of an attachment.
    fn rank(&self) -> u8 {
        match self {
            Planned::HideDir(_) | Planned::HideFile(_) => 0,
            Planned::SkeletonDir(_) | Planned::SkeletonFile(_) => 1,
            Planned::Attach { .. } => 2,
            Planned::Restrict { .. } => 3,
        }
    }
}

/// Compile the deny-under-allow boundaries of the ordered policy into a
/// [`ns::MountPlan`]. Rule paths are processed ancestors-first; each path
/// where the final effect denies a right that a Landlock grant would allow
/// gets a mask, and each path the policy re-allows beneath a mask gets its
/// real subtree cloned and attached back.
fn plan_masks(
    rules: &[NormalizedRule],
    read_grants: &BTreeSet<PathBuf>,
    write_grants: &BTreeSet<PathBuf>,
    execute_grants: &BTreeSet<PathBuf>,
) -> Result<ns::MountPlan> {
    let grants_for = |right| match right {
        FsRight::Read => read_grants,
        FsRight::Write => write_grants,
        FsRight::Execute => execute_grants,
    };

    // Unique rule paths in component order: ancestors before descendants.
    let paths: BTreeSet<&Path> = rules.iter().map(|rule| rule.path.as_path()).collect();

    let mut specials: Vec<(PathBuf, Special)> = Vec::new();
    let mut planned: Vec<Planned> = Vec::new();
    let mut clone_sources: Vec<PathBuf> = Vec::new();
    let mut skeleton_dirs: BTreeSet<PathBuf> = BTreeSet::new();
    let mut sealed_hides: BTreeSet<PathBuf> = BTreeSet::new();

    for &path in &paths {
        let is_dir = std::fs::symlink_metadata(path)
            .map_err(|err| Error::confinement("landlock", err))?
            .is_dir();

        let mut allowed = 0u8;
        let mut denied_covered = 0u8;
        for right in RIGHTS {
            match final_effect(rules, right, path) {
                // A final Allow always sits beneath (or on) a grant root, so
                // Landlock permits it; nothing to check.
                RuleEffect::Allow => allowed |= right_bit(right),
                // A final Deny only needs enforcement when a grant would
                // otherwise cover the path.
                RuleEffect::Deny => {
                    if grants_for(right).iter().any(|g| path.starts_with(g)) {
                        denied_covered |= right_bit(right);
                    }
                }
            }
        }

        let context = mask_context(&specials, path);
        let blocked = if context.hidden {
            ALL_RIGHTS
        } else {
            context.blocked
        };

        // Re-attach the real subtree when the policy allows a right here that
        // the mask chain above blocks.
        let attached = allowed & blocked != 0;
        if attached {
            if context.hidden {
                if denied_covered & READ_BIT != 0 {
                    return Err(Error::Unsupported(format!(
                        "cannot enforce this ordered policy on Linux: `{}` \
                         re-allows write or execute beneath a read-denied \
                         parent, and re-exposing it would also re-expose the \
                         read access the policy denies; re-allow read on it \
                         too, or move it out of the read-denied subtree",
                        path.display()
                    )));
                }
                let hide_root = context
                    .hide_root
                    .as_deref()
                    .expect("hidden context carries its hide root");
                let mut ancestor = path.parent();
                while let Some(dir) = ancestor {
                    if dir == hide_root {
                        break;
                    }
                    skeleton_dirs.insert(dir.to_path_buf());
                    ancestor = dir.parent();
                }
                if is_dir {
                    skeleton_dirs.insert(path.to_path_buf());
                } else {
                    planned.push(Planned::SkeletonFile(path.to_path_buf()));
                }
                sealed_hides.insert(hide_root.to_path_buf());
            }
            let slot = clone_sources.len();
            clone_sources.push(path.to_path_buf());
            planned.push(Planned::Attach {
                slot,
                path: path.to_path_buf(),
            });
            specials.push((path.to_path_buf(), Special::Exposed { restricted: 0 }));
        }

        // Rights that remain reachable at this path but are denied: attach
        // reset the mask chain, otherwise whatever it blocks needs no second
        // mask.
        let residual = if attached {
            denied_covered
        } else {
            denied_covered & !blocked
        };
        if residual == 0 {
            continue;
        }
        if residual & READ_BIT != 0 {
            if allowed & (WRITE_BIT | EXEC_BIT) != 0 {
                return Err(Error::Unsupported(format!(
                    "cannot enforce this ordered policy on Linux: read is \
                     denied at `{}` while write or execute stays allowed \
                     there, and a hidden path cannot remain writable or \
                     executable; deny write/execute on it too, or drop the \
                     read deny",
                    path.display()
                )));
            }
            planned.push(if is_dir {
                Planned::HideDir(path.to_path_buf())
            } else {
                Planned::HideFile(path.to_path_buf())
            });
            specials.push((path.to_path_buf(), Special::Hide));
        } else {
            planned.push(Planned::Restrict {
                path: path.to_path_buf(),
                rights: residual,
                recursive: is_dir,
            });
            if attached {
                if let Some((_, Special::Exposed { restricted })) = specials.last_mut() {
                    *restricted |= residual;
                }
            } else {
                specials.push((path.to_path_buf(), Special::Restricted { rights: residual }));
            }
        }
    }

    for dir in &skeleton_dirs {
        planned.push(Planned::SkeletonDir(dir.clone()));
    }
    planned.sort_by(|a, b| {
        let key = |p: &Planned| (p.path().components().count(), p.rank());
        key(a).cmp(&key(b)).then_with(|| a.path().cmp(b.path()))
    });

    let ops = planned
        .iter()
        .map(|entry| {
            Ok(match entry {
                Planned::HideDir(path) => {
                    let seal_later = sealed_hides.contains(path);
                    ns::MaskOp::HideDir {
                        path: mount_cstring(path)?,
                        // Traversal-only when re-allowed descendants are
                        // attached inside; fully closed otherwise.
                        data: CString::from(if seal_later { c"mode=0111" } else { c"mode=0" }),
                        seal_later,
                    }
                }
                Planned::HideFile(path) => ns::MaskOp::HideFile {
                    path: mount_cstring(path)?,
                },
                Planned::SkeletonDir(path) => ns::MaskOp::SkeletonDir {
                    path: mount_cstring(path)?,
                },
                Planned::SkeletonFile(path) => ns::MaskOp::SkeletonFile {
                    path: mount_cstring(path)?,
                },
                Planned::Attach { slot, path } => ns::MaskOp::Attach {
                    slot: *slot,
                    path: mount_cstring(path)?,
                },
                Planned::Restrict {
                    path,
                    rights,
                    recursive,
                } => {
                    let mut attr_set = 0;
                    if rights & WRITE_BIT != 0 {
                        attr_set |= ns::MOUNT_ATTR_RDONLY;
                    }
                    if rights & EXEC_BIT != 0 {
                        attr_set |= ns::MOUNT_ATTR_NOEXEC;
                    }
                    ns::MaskOp::Restrict {
                        path: mount_cstring(path)?,
                        attr_set,
                        recursive: *recursive,
                    }
                }
            })
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(ns::MountPlan {
        clone_sources: clone_sources
            .iter()
            .map(|p| mount_cstring(p))
            .collect::<Result<Vec<_>>>()?,
        ops,
        seal_readonly: sealed_hides
            .iter()
            .map(|p| mount_cstring(p))
            .collect::<Result<Vec<_>>>()?,
    })
}

fn mount_cstring(path: &Path) -> Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|err| Error::confinement("mount masking", err))
}

fn add_path_rules(
    mut ruleset: RulesetCreated,
    paths: &BTreeSet<PathBuf>,
    access: BitFlags<AccessFs>,
) -> Result<RulesetCreated> {
    for path in paths {
        let fd = PathFd::new(path).map_err(|err| Error::confinement("landlock", err))?;
        ruleset = ruleset
            .add_rule(PathBeneath::new(fd, access))
            .map_err(|err| Error::confinement("landlock", err))?;
    }
    Ok(ruleset)
}

fn access_for_right(right: FsRight, abi: ABI) -> BitFlags<AccessFs> {
    match right {
        FsRight::Read => read_access(),
        FsRight::Write => AccessFs::from_write(abi),
        FsRight::Execute => execute_access(),
    }
}

fn read_access() -> BitFlags<AccessFs> {
    make_bitflags!(AccessFs::{ReadFile | ReadDir})
}

fn execute_access() -> BitFlags<AccessFs> {
    make_bitflags!(AccessFs::{Execute})
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canon(path: &Path) -> PathBuf {
        std::fs::canonicalize(path).unwrap()
    }

    fn c(path: &Path) -> CString {
        mount_cstring(&canon(path)).unwrap()
    }

    #[test]
    fn allow_parent_deny_child_grants_parent_and_hides_child() {
        let temp = tempfile::tempdir().unwrap();
        let public = temp.path().join("public.txt");
        let secret = temp.path().join("secret.txt");
        std::fs::write(&public, b"public").unwrap();
        std::fs::write(&secret, b"secret").unwrap();

        let compiled = compile(&[
            FsAccess::ReadAllow(temp.path().into()),
            FsAccess::ReadDeny(secret.clone()),
        ])
        .unwrap();

        // The parent is granted wholesale — future siblings are covered.
        assert_eq!(compiled.read_paths, BTreeSet::from([canon(temp.path())]));
        assert_eq!(
            compiled.mount_plan.ops,
            vec![ns::MaskOp::HideFile { path: c(&secret) }]
        );
        assert!(compiled.mount_plan.clone_sources.is_empty());
        assert!(compiled.mount_plan.seal_readonly.is_empty());
    }

    #[test]
    fn allow_parent_deny_child_allow_grandchild_attaches_grandchild() {
        let temp = tempfile::tempdir().unwrap();
        let child = temp.path().join("child");
        let grandchild = child.join("grandchild.txt");
        let other = child.join("other.txt");
        std::fs::create_dir(&child).unwrap();
        std::fs::write(&grandchild, b"grandchild").unwrap();
        std::fs::write(&other, b"other").unwrap();

        let compiled = compile(&[
            FsAccess::ReadAllow(temp.path().into()),
            FsAccess::ReadDeny(child.clone()),
            FsAccess::ReadAllow(grandchild.clone()),
        ])
        .unwrap();

        assert_eq!(
            compiled.read_paths,
            BTreeSet::from([canon(temp.path()), canon(&grandchild)])
        );
        assert_eq!(compiled.mount_plan.clone_sources, vec![c(&grandchild)]);
        assert_eq!(
            compiled.mount_plan.ops,
            vec![
                ns::MaskOp::HideDir {
                    path: c(&child),
                    data: CString::from(c"mode=0111"),
                    seal_later: true,
                },
                ns::MaskOp::SkeletonFile {
                    path: c(&grandchild)
                },
                ns::MaskOp::Attach {
                    slot: 0,
                    path: c(&grandchild)
                },
            ]
        );
        assert_eq!(compiled.mount_plan.seal_readonly, vec![c(&child)]);
    }

    #[test]
    fn write_deny_under_write_allow_restricts_readonly() {
        let temp = tempfile::tempdir().unwrap();
        let locked = temp.path().join("locked");
        std::fs::create_dir(&locked).unwrap();

        let compiled = compile(&[
            FsAccess::ReadAllow(temp.path().into()),
            FsAccess::WriteAllow(temp.path().into()),
            FsAccess::WriteDeny(locked.clone()),
        ])
        .unwrap();

        assert_eq!(
            compiled.mount_plan.ops,
            vec![ns::MaskOp::Restrict {
                path: c(&locked),
                attr_set: ns::MOUNT_ATTR_RDONLY,
                recursive: true,
            }]
        );
    }

    #[test]
    fn write_and_execute_deny_combine_into_one_restrict() {
        let temp = tempfile::tempdir().unwrap();
        let locked = temp.path().join("locked");
        std::fs::create_dir(&locked).unwrap();

        let compiled = compile(&[
            FsAccess::WriteAllow(temp.path().into()),
            FsAccess::ExecuteAllow(temp.path().into()),
            FsAccess::WriteDeny(locked.clone()),
            FsAccess::ExecuteDeny(locked.clone()),
        ])
        .unwrap();

        assert_eq!(
            compiled.mount_plan.ops,
            vec![ns::MaskOp::Restrict {
                path: c(&locked),
                attr_set: ns::MOUNT_ATTR_RDONLY | ns::MOUNT_ATTR_NOEXEC,
                recursive: true,
            }]
        );
    }

    #[test]
    fn read_deny_with_covered_write_allow_is_unsupported() {
        let temp = tempfile::tempdir().unwrap();
        let secret = temp.path().join("secret");
        std::fs::create_dir(&secret).unwrap();

        let result = compile(&[
            FsAccess::ReadAllow(temp.path().into()),
            FsAccess::WriteAllow(temp.path().into()),
            FsAccess::ReadDeny(secret),
        ]);

        assert!(matches!(result, Err(Error::Unsupported(_))));
    }

    #[test]
    fn write_reallow_beneath_read_denied_parent_is_unsupported() {
        let temp = tempfile::tempdir().unwrap();
        let secret = temp.path().join("secret");
        let inner = secret.join("inner");
        std::fs::create_dir_all(&inner).unwrap();

        let result = compile(&[
            FsAccess::ReadAllow(temp.path().into()),
            FsAccess::ReadDeny(secret),
            FsAccess::WriteAllow(inner),
        ]);

        assert!(matches!(result, Err(Error::Unsupported(_))));
    }

    #[test]
    fn deny_parent_allow_child_grants_child_without_masks() {
        let temp = tempfile::tempdir().unwrap();
        let child = temp.path().join("child");
        let sibling = temp.path().join("sibling");
        std::fs::create_dir(&child).unwrap();
        std::fs::create_dir(&sibling).unwrap();

        let compiled = compile(&[
            FsAccess::ReadDeny(temp.path().into()),
            FsAccess::ReadAllow(child.clone()),
        ])
        .unwrap();

        // The deny has no covering grant: default-deny already enforces it.
        assert_eq!(compiled.read_paths, BTreeSet::from([canon(&child)]));
        assert!(compiled.mount_plan.is_empty());
    }

    #[test]
    fn uncovered_deny_needs_no_mask() {
        let temp = tempfile::tempdir().unwrap();
        let unrelated = tempfile::tempdir().unwrap();

        let compiled = compile(&[
            FsAccess::ReadAllow(temp.path().into()),
            FsAccess::ReadDeny(unrelated.path().into()),
        ])
        .unwrap();

        assert!(compiled.mount_plan.is_empty());
    }

    #[test]
    fn allow_deny_allow_same_path_final_effect_is_allow() {
        let temp = tempfile::tempdir().unwrap();
        let compiled = compile(&[
            FsAccess::ReadAllow(temp.path().into()),
            FsAccess::ReadDeny(temp.path().into()),
            FsAccess::ReadAllow(temp.path().into()),
        ])
        .unwrap();

        assert_eq!(compiled.read_paths, BTreeSet::from([canon(temp.path())]));
        assert!(compiled.mount_plan.is_empty());
    }

    #[test]
    fn allow_deny_same_path_final_effect_is_deny() {
        let temp = tempfile::tempdir().unwrap();
        let compiled = compile(&[
            FsAccess::ReadAllow(temp.path().into()),
            FsAccess::ReadDeny(temp.path().into()),
        ])
        .unwrap();

        assert!(compiled.read_paths.is_empty());
        assert!(compiled.mount_plan.is_empty());
    }

    #[test]
    fn missing_rule_path_fails_closed_during_normalization() {
        let temp = tempfile::tempdir().unwrap();
        let missing = temp.path().join("future-secret");

        let result = compile(&[
            FsAccess::ReadAllow(temp.path().into()),
            FsAccess::ReadDeny(missing),
        ]);

        assert!(matches!(
            result,
            Err(Error::Confinement {
                stage: "landlock",
                ..
            })
        ));
    }

    #[test]
    fn write_access_uses_write_only_rights() {
        let write = access_for_right(FsRight::Write, ABI::V2);

        assert_eq!(write, AccessFs::from_write(ABI::V2));
        // Cross-directory rename/link (issue #24) rides on the v2 Refer right.
        assert!(write.contains(AccessFs::Refer));
        assert!(!write.intersects(read_access()));
        assert!(!write.intersects(execute_access()));
    }
}
