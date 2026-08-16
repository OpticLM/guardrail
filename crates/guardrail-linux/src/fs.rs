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
//!
//! Both layers are applied through descriptors *pinned at compile time*, never
//! by re-resolving a path string later — see [`Pin`].

use std::collections::BTreeSet;
use std::ffi::{CStr, CString};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use landlock::{
    ABI, Access, AccessFs, BitFlags, CompatLevel, Compatible, PathBeneath, Ruleset, RulesetAttr,
    RulesetCreated, RulesetCreatedAttr, make_bitflags,
};

use guardrail_core::{Error, FsAccess, Result};

use crate::ns;

// Stable Landlock UAPI values through ABI v2. The private IPC-mount rules
// allow every V2 read/write/create/remove/refer right, but not Execute.
const LANDLOCK_RULE_PATH_BENEATH: libc::c_uint = 1;
const PRIVATE_IPC_ACCESS_FS: u64 = 0x3ffe;

#[repr(C, packed)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: libc::c_int,
}

/// A rule path pinned to the inode it resolved to when the policy was
/// compiled.
///
/// Rule paths are canonicalized and opened exactly once, in [`compile`] — that
/// is, in `LinuxBackend::new`. Resolving the path string again at spawn time
/// would make the policy follow the *name* rather than the inode it was
/// compiled against: a sandboxed child that may write a directory on the way
/// to a policy path could move that directory aside between two spawns and
/// leave a symlink or a decoy in its place, so the next spawn's grant or mask
/// landed on an inode of the child's choosing — widening a grant or missing a
/// deny.
///
/// The two layers consume the pin differently, because [`prepare`] runs in the
/// parent while the masks are installed in the child:
///
/// * Landlock rules are built pre-fork, so they use `fd` directly and never
///   resolve the path a second time;
/// * the child unshares its own mount namespace first, and the mount syscalls
///   reject a descriptor belonging to another namespace, so it re-resolves the
///   path and checks the result against [`Pin::identity`] before masking it —
///   a redirected path fails the spawn rather than masking the wrong inode.
///   Keeping `fd` open for the backend's lifetime is what makes that check
///   sound: the pinned inode cannot be freed and its number recycled beneath
///   a decoy.
///
/// The consequence to be aware of: replacing a policy path after the backend
/// is constructed does not re-point the policy. The sandbox keeps confining
/// the inode the policy was validated against.
#[derive(Debug)]
struct Pin {
    path: PathBuf,
    fd: OwnedFd,
}

impl Pin {
    /// The `(device, inode)` this path resolved to when it was pinned.
    fn identity(&self) -> Result<(libc::dev_t, libc::ino_t)> {
        // SAFETY: `stat` is a plain C struct; an all-zero value is a valid
        // initial state for `fstat` to overwrite.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: the descriptor is owned by `self` and `st` is a valid
        // out-pointer for the duration of the call.
        if unsafe { libc::fstat(self.fd.as_raw_fd(), &mut st) } != 0 {
            return Err(Error::confinement(
                "landlock",
                std::io::Error::last_os_error(),
            ));
        }
        Ok((st.st_dev, st.st_ino))
    }
}

#[derive(Debug)]
pub(crate) struct CompiledRules {
    /// Every distinct rule path, sorted, so a path's pin index is stable.
    pins: Vec<Pin>,
    read_paths: BTreeSet<PathBuf>,
    write_paths: BTreeSet<PathBuf>,
    execute_paths: BTreeSet<PathBuf>,
    pub(crate) mount_plan: ns::MountPlan,
}

impl CompiledRules {
    /// Keep the pins alive for the backend's lifetime: the child's masking
    /// checks a re-resolved path against [`Pin::identity`], and an open
    /// descriptor is what stops the pinned inode from being freed and its
    /// number reused by a decoy.
    #[cfg(test)]
    fn pin_count(&self) -> usize {
        self.pins.len()
    }
}

/// Compile ordered filesystem allow/deny rules into positive Landlock paths
/// and a mount-masking plan for deny-under-allow boundaries.
///
/// This runs in the parent before `fork()`, so policy compilation errors
/// remain structured [`Error::Confinement`] / [`Error::Unsupported`] values
/// instead of being collapsed into a `pre_exec` spawn failure. It is also
/// where every rule path is pinned (see [`Pin`]).
pub(crate) fn compile(rules: &[FsAccess]) -> Result<CompiledRules> {
    let normalized = normalize_rules(rules)?;
    let pins = pin_rule_paths(&normalized)?;
    let read_paths = allow_roots(&normalized, FsRight::Read);
    let write_paths = allow_roots(&normalized, FsRight::Write);
    let execute_paths = allow_roots(&normalized, FsRight::Execute);
    let mount_plan = plan_masks(
        &normalized,
        &pins,
        &read_paths,
        &write_paths,
        &execute_paths,
    )?;
    Ok(CompiledRules {
        pins,
        read_paths,
        write_paths,
        execute_paths,
        mount_plan,
    })
}

/// Open one `O_PATH` descriptor per distinct rule path. Sorted, so a path's
/// index into the result is stable for the mask plan that references it.
fn pin_rule_paths(rules: &[NormalizedRule]) -> Result<Vec<Pin>> {
    let paths: BTreeSet<&Path> = rules.iter().map(|rule| rule.path.as_path()).collect();
    paths
        .into_iter()
        .map(|path| {
            let c_path = mount_cstring(path)?;
            // SAFETY: the path is NUL-terminated and the flags are scalar.
            let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
            if fd < 0 {
                return Err(Error::confinement(
                    "landlock",
                    std::io::Error::last_os_error(),
                ));
            }
            Ok(Pin {
                path: path.to_path_buf(),
                // SAFETY: `fd` was just returned by a successful `open` and is
                // owned by nothing else.
                fd: unsafe { OwnedFd::from_raw_fd(fd) },
            })
        })
        .collect()
}

/// The pin index of a rule path. Every path reaching this came from the same
/// normalized rule set the pins were built from.
fn pin_index(pins: &[Pin], path: &Path) -> usize {
    pins.iter()
        .position(|pin| pin.path == path)
        .expect("every rule path is pinned")
}

/// The masking target for a rule path: the path the child re-resolves in its
/// own mount namespace, plus the identity that resolution must produce.
fn target_for(pins: &[Pin], path: &Path) -> Result<ns::Target> {
    let pin = pins
        .get(pin_index(pins, path))
        .expect("pin_index returns an in-range index");
    let (dev, ino) = pin.identity()?;
    Ok(ns::Target {
        path: mount_cstring(path)?,
        dev,
        ino,
    })
}

/// A Landlock ruleset built in the parent with all host-path rules. The child
/// adds only its newly mounted private IPC filesystems before enforcement.
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

    /// Add the child-private `/dev/mqueue` and `/dev/shm` hierarchies to this
    /// spawn's ruleset. Called after both filesystems are mounted but before
    /// the ruleset is enforced, so these rules identify the private mounts
    /// rather than their hidden host counterparts. Only raw syscalls are used
    /// in the post-fork child.
    pub(crate) fn allow_private_ipc(&self) -> std::io::Result<()> {
        for path in [c"/dev/mqueue", c"/dev/shm"] {
            self.allow_private_ipc_path(path)?;
        }
        Ok(())
    }

    fn allow_private_ipc_path(&self, path: &CStr) -> std::io::Result<()> {
        // SAFETY: path is NUL-terminated and flags are scalar.
        let path_fd = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if path_fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let attr = LandlockPathBeneathAttr {
            allowed_access: PRIVATE_IPC_ACCESS_FS,
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
/// `fork()`. The child adds its private IPC filesystems with raw syscalls, then
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

    ruleset = add_pinned_rules(
        ruleset,
        &rules.pins,
        &rules.read_paths,
        access_for_right(FsRight::Read, abi),
    )?;
    ruleset = add_pinned_rules(
        ruleset,
        &rules.pins,
        &rules.write_paths,
        access_for_right(FsRight::Write, abi),
    )?;
    ruleset = add_pinned_rules(
        ruleset,
        &rules.pins,
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

/// Whether the sandbox could rename `dir`. `rename(2)` is mediated by
/// Landlock's `Refer` right on the *parent* directory — which every write
/// grant carries — so a directory is movable exactly when write is finally
/// allowed one level up.
fn renameable_by_the_sandbox(rules: &[NormalizedRule], dir: &Path) -> bool {
    dir.parent()
        .is_some_and(|parent| final_effect(rules, FsRight::Write, parent) == RuleEffect::Allow)
}

/// Refuse policies whose paths the sandbox could relocate.
///
/// Masks and grants are bound to inodes, not names, so within one sandbox a
/// rename changes nothing: a mount travels with the directory it is glued to,
/// and a spawn whose target stopped naming its compiled inode is refused. But
/// the rename outlives the process. A child can move a directory aside, leave
/// a decoy at the old name, and wait — a later run compiles this same policy
/// against the rewritten tree, and its grant or mask lands on the decoy while
/// the real data sits beside it under the surrounding allow rule. Pinning
/// inside one process cannot see that, and persisting inode identity across
/// runs would break on every legitimate `git checkout` or editor rewrite.
///
/// So the shape is rejected up front. A policy path is safe when neither it
/// nor any directory above it can be renamed by the sandbox, which holds when
/// each is either a mount point in this plan (renaming one fails with `EBUSY`)
/// or sits where the policy grants no write on its parent. That keeps the
/// common shapes — `WriteAllow(project)` with `WriteDeny(project/.git)` is
/// fine, because moving `project` needs rights the policy never grants above
/// its own root — and rejects a deny buried under a directory the sandbox may
/// freely move.
fn reject_relocatable_policy_paths(
    rules: &[NormalizedRule],
    planned: &[Planned],
    grants: [&BTreeSet<PathBuf>; 3],
) -> Result<()> {
    let mounted: BTreeSet<&Path> = planned
        .iter()
        .filter(|entry| entry.is_mount())
        .map(Planned::path)
        .collect();

    // Everything the policy identifies by path and must still identify next
    // run: the Landlock grant roots and every masked deny boundary.
    let policy_paths: BTreeSet<&Path> = grants
        .into_iter()
        .flatten()
        .map(PathBuf::as_path)
        .chain(mounted.iter().copied())
        .collect();

    for path in policy_paths {
        let mut candidate = Some(path);
        while let Some(dir) = candidate {
            if !mounted.contains(dir) && renameable_by_the_sandbox(rules, dir) {
                return Err(Error::Unsupported(not_durable(path, dir)));
            }
            candidate = dir.parent();
        }
    }
    Ok(())
}

/// The refusal [`reject_relocatable_policy_paths`] raises, phrased for whether
/// the movable directory is the rule path itself or one above it.
fn not_durable(path: &Path, dir: &Path) -> String {
    let common = "A child can move it aside, leave a decoy at the old name, and \
                  a later run of this policy would confine the decoy instead of \
                  the real path.";
    if path == dir {
        format!(
            "cannot enforce this ordered policy on Linux: the rule for `{}` is \
             not durable, because the sandbox may rename it — write is allowed \
             on its parent. {common} Deny write on `{}` too, which makes it a \
             mount point that cannot be renamed, or keep it out of a \
             write-allowed subtree",
            path.display(),
            path.display()
        )
    } else {
        format!(
            "cannot enforce this ordered policy on Linux: the rule for `{}` is \
             not durable, because the sandbox may rename `{}` on the way to it \
             — write is allowed on that directory's parent. {common} Deny write \
             on `{}` as well, which makes it a mount point that cannot be \
             renamed, or keep `{}` out of a write-allowed subtree",
            path.display(),
            dir.display(),
            dir.display(),
            path.display()
        )
    }
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

    /// Whether this operation installs a mount at its path. Renaming a mount
    /// point fails with `EBUSY`, so a mount on the way to a policy path is
    /// what keeps the sandbox from relocating it — see
    /// [`reject_relocatable_policy_paths`]. Skeletons are plain entries
    /// created inside a hiding tmpfs, not mounts.
    fn is_mount(&self) -> bool {
        match self {
            Planned::HideDir(_)
            | Planned::HideFile(_)
            | Planned::Attach { .. }
            | Planned::Restrict { .. } => true,
            Planned::SkeletonDir(_) | Planned::SkeletonFile(_) => false,
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
///
/// Masks and clone sources are emitted as [`ns::Target`]s carrying the pinned
/// inode identity, so the child installs them on the inodes the policy was
/// compiled against or refuses to spawn. The skeleton and attach operations
/// stay plain paths: they target entries *inside* a hiding tmpfs this plan
/// mounts, which has no compile-time inode to pin. A swapped path prefix can
/// therefore still misplace a re-allowed subtree, but not reveal a masked one
/// — the hide itself is verified, and the Landlock grant for the re-allowed
/// path is pinned too, so a misplaced attachment is reachable only where the
/// policy already allowed it.
fn plan_masks(
    rules: &[NormalizedRule],
    pins: &[Pin],
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

    // Every mount this plan installs is known now, so the durability of the
    // paths it is all keyed on can be settled before anything else is built.
    reject_relocatable_policy_paths(rules, &planned, [read_grants, write_grants, execute_grants])?;

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
                        target: target_for(pins, path)?,
                        // Traversal-only when re-allowed descendants are
                        // attached inside; fully closed otherwise.
                        mode: CString::from(if seal_later { c"0111" } else { c"0" }),
                        seal_later,
                    }
                }
                Planned::HideFile(path) => ns::MaskOp::HideFile {
                    target: target_for(pins, path)?,
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
                        target: target_for(pins, path)?,
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
            .map(|path| target_for(pins, path))
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

/// Grant `access` beneath each allow root, identifying the root by its pinned
/// descriptor rather than re-opening its path. `PathBeneath` only borrows the
/// descriptor, so the pin stays owned by [`CompiledRules`] and usable by the
/// next spawn.
fn add_pinned_rules(
    mut ruleset: RulesetCreated,
    pins: &[Pin],
    paths: &BTreeSet<PathBuf>,
    access: BitFlags<AccessFs>,
) -> Result<RulesetCreated> {
    for path in paths {
        let pin = pins
            .get(pin_index(pins, path))
            .expect("pin_index returns an in-range index");
        ruleset = ruleset
            .add_rule(PathBeneath::new(&pin.fd, access))
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

    impl CompiledRules {
        /// The mask target a plan carries for `path`.
        fn target(&self, path: &Path) -> ns::Target {
            target_for(&self.pins, &canon(path)).unwrap()
        }
    }

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
            vec![ns::MaskOp::HideFile {
                target: compiled.target(&secret),
            }]
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
        assert_eq!(
            compiled.mount_plan.clone_sources,
            vec![compiled.target(&grandchild)]
        );
        assert_eq!(
            compiled.mount_plan.ops,
            vec![
                ns::MaskOp::HideDir {
                    target: compiled.target(&child),
                    mode: CString::from(c"0111"),
                    seal_later: true,
                },
                // Skeletons and attachments land inside the tmpfs mounted
                // above, which has no compile-time inode to pin.
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
                target: compiled.target(&locked),
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
                target: compiled.target(&locked),
                attr_set: ns::MOUNT_ATTR_RDONLY | ns::MOUNT_ATTR_NOEXEC,
                recursive: true,
            }]
        );
    }

    #[test]
    fn deny_beneath_a_sandbox_movable_directory_is_unsupported() {
        let temp = tempfile::tempdir().unwrap();
        let vault = temp.path().join("vault");
        let locked = vault.join("locked");
        std::fs::create_dir_all(&locked).unwrap();

        // `vault` is inside the write grant, so the sandbox can rename it and
        // stage a decoy that a later run of this policy would mask instead.
        let result = compile(&[
            FsAccess::ReadAllow(temp.path().into()),
            FsAccess::WriteAllow(temp.path().into()),
            FsAccess::WriteDeny(locked),
        ]);

        assert!(matches!(result, Err(Error::Unsupported(_))), "{result:?}");
    }

    #[test]
    fn deny_beneath_a_denied_directory_is_supported() {
        let temp = tempfile::tempdir().unwrap();
        let vault = temp.path().join("vault");
        let locked = vault.join("locked");
        std::fs::create_dir_all(&locked).unwrap();

        // Denying write on `vault` too makes it a mount point, which cannot be
        // renamed (EBUSY) — so nothing on the way to `locked` can move.
        let compiled = compile(&[
            FsAccess::ReadAllow(temp.path().into()),
            FsAccess::WriteAllow(temp.path().into()),
            FsAccess::WriteDeny(vault.clone()),
            FsAccess::WriteDeny(locked),
        ])
        .unwrap();

        // Only `vault` needs a mask: the recursive read-only bind already
        // covers everything beneath it.
        assert_eq!(
            compiled.mount_plan.ops,
            vec![ns::MaskOp::Restrict {
                target: compiled.target(&vault),
                attr_set: ns::MOUNT_ATTR_RDONLY,
                recursive: true,
            }]
        );
    }

    #[test]
    fn deny_directly_beneath_its_write_grant_is_supported() {
        let temp = tempfile::tempdir().unwrap();
        let locked = temp.path().join("locked");
        std::fs::create_dir(&locked).unwrap();

        // The shape real policies use (`WriteAllow(project)` +
        // `WriteDeny(project/.git)`): moving the grant root needs rights on
        // its parent, which this policy never grants.
        let compiled = compile(&[
            FsAccess::ReadAllow(temp.path().into()),
            FsAccess::WriteAllow(temp.path().into()),
            FsAccess::WriteDeny(locked.clone()),
        ])
        .unwrap();

        assert_eq!(
            compiled.mount_plan.ops,
            vec![ns::MaskOp::Restrict {
                target: compiled.target(&locked),
                attr_set: ns::MOUNT_ATTR_RDONLY,
                recursive: true,
            }]
        );
    }

    #[test]
    fn allow_root_inside_a_write_grant_is_unsupported() {
        let temp = tempfile::tempdir().unwrap();
        let work = temp.path().join("work");
        let sub = work.join("sub");
        std::fs::create_dir_all(&sub).unwrap();

        // The sandbox can rename `sub`, so a later run's Landlock grant would
        // be issued over whatever the name points at by then.
        let result = compile(&[FsAccess::ReadAllow(sub), FsAccess::WriteAllow(work)]);

        assert!(matches!(result, Err(Error::Unsupported(_))), "{result:?}");
    }

    #[test]
    fn read_only_policies_are_never_relocatable() {
        let temp = tempfile::tempdir().unwrap();
        let work = temp.path().join("work");
        let sub = work.join("sub");
        std::fs::create_dir_all(&sub).unwrap();

        // Without a write grant the sandbox cannot rename anything, so nesting
        // is fine however deep it goes.
        let compiled =
            compile(&[FsAccess::ReadAllow(work), FsAccess::ReadAllow(sub.clone())]).unwrap();

        assert!(compiled.read_paths.contains(&canon(&sub)));
    }

    #[test]
    fn every_rule_path_is_pinned_once() {
        let temp = tempfile::tempdir().unwrap();
        let locked = temp.path().join("locked");
        std::fs::create_dir(&locked).unwrap();

        let compiled = compile(&[
            FsAccess::ReadAllow(temp.path().into()),
            FsAccess::WriteAllow(temp.path().into()),
            FsAccess::WriteDeny(locked.clone()),
        ])
        .unwrap();

        // Two distinct paths across three rules: pins are per path, not per
        // rule.
        let paths: Vec<&Path> = compiled.pins.iter().map(|pin| pin.path.as_path()).collect();
        assert_eq!(paths, vec![canon(temp.path()), canon(&locked)]);
        assert_eq!(compiled.pin_count(), 2);

        // Each pin records the identity the child must re-observe, and the
        // descriptor stays open so that inode cannot be recycled.
        let identity = compiled.target(&locked);
        let meta = std::fs::metadata(&locked).unwrap();
        use std::os::unix::fs::MetadataExt;
        assert_eq!((identity.dev, identity.ino), (meta.dev(), meta.ino()));
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
