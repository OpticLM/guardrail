//! Per-spawn IPC isolation and mount-namespace masking.
//!
//! Every child gets a fresh IPC namespace for SysV IPC and POSIX message
//! queues, a corresponding private `/dev/mqueue` mount, and a private
//! `/dev/shm` tmpfs for POSIX shared memory and named semaphores. The tmpfs is
//! capped at 64 MiB; both private mounts use `nosuid,nodev,noexec`.
//!
//! Landlock rules are purely additive grants, so an ordered policy such as
//! `allow(root)` then `deny(root/secret)` cannot be expressed as Landlock
//! rules alone without freezing the directory's contents at compile time
//! (issue #19). Instead, the backend grants the allowed parent wholesale and
//! enforces each deny boundary with a mount glued over the denied path:
//!
//! * read denied — the path is overmounted with an empty read-only `mode=0`
//!   tmpfs (directories) or an empty read-only `mode=0` file (regular files),
//!   making the real content unreachable no matter when it was created;
//! * only write denied — a recursive read-only self-bind leaves reads (and
//!   future files) visible while writes fail with `EROFS`;
//! * only execute denied — the same self-bind with `MOUNT_ATTR_NOEXEC`.
//!
//! Paths re-allowed beneath a masked subtree are cloned with
//! `open_tree(OPEN_TREE_CLONE)` *before* the mask shadows them and attached
//! back with `move_mount`, through a traversal-only (`mode=0111`) skeleton
//! when the mask is a hiding tmpfs. Bind clones are live mounts, so files
//! created later on either side keep following the policy.
//!
//! The mounts live in a per-spawn user + mount namespace created alongside
//! the IPC namespace inside `pre_exec` (the forked child is single-threaded,
//! which `unshare(CLONE_NEWUSER)` requires). Propagation is set to
//! `MS_SLAVE|MS_REC` first so nothing leaks back to the host. After masking,
//! a *second* `unshare(CLONE_NEWUSER|CLONE_NEWNS)` locks every mask mount
//! (`MNT_LOCKED`): even a child legitimately permitted to create nested
//! namespaces (`UserNamespacePolicy::Allow`, or a root euid) can stack new
//! mounts but can never unmount a mask to reveal what it hides. Under the
//! default `UserNamespacePolicy::Deny` the seccomp filters additionally trap
//! the whole mount machinery.
//!
//! Masks are installed on the inode the policy was compiled against, not on
//! whatever the denied path happens to name at spawn time. The child cannot
//! simply inherit the parent's pinned descriptor — it unshares its own mount
//! namespace first, and the mount syscalls reject a descriptor belonging to
//! another namespace — so it re-resolves each [`Target`] and checks the result
//! against the identity the parent recorded (see [`crate::fs::Pin`]). The
//! descriptor that passes the check is the one every subsequent syscall uses,
//! so there is no window between checking and mounting. A path that no longer
//! names its compiled inode fails the spawn instead of masking the wrong
//! thing, which is what stops a sandboxed child from moving a directory aside
//! between two spawns and having the next spawn's mask land on a decoy.
//!
//! Each mask is built with the new mount API: `open_tree(OPEN_TREE_CLONE)` or
//! `fsmount` produces a detached mount, `mount_setattr` strips rights from it
//! while it is still detached, and `move_mount` attaches it onto the verified
//! descriptor with `MOVE_MOUNT_T_EMPTY_PATH`.
//!
//! Everything here follows the crate's `pre_exec` contract: plans are
//! compiled to `CString`s and fixed buffers in the parent, and the child only
//! issues raw syscalls over that prepared data.

use std::ffi::{CStr, CString};
use std::io;

use guardrail_core::{Error, Result};

// Kernel ABI constants for the new mount API (include/uapi/linux/mount.h,
// include/uapi/linux/fcntl.h). Defined locally because the libc crate does
// not expose all of them on every supported target (e.g. musl); the values
// are stable kernel ABI, present since Linux 5.2 (5.12 for mount_setattr) —
// older than the 5.19 Landlock ABI v2 floor `probe_support` already
// enforces.
const OPEN_TREE_CLONE: libc::c_uint = 0x1;
const OPEN_TREE_CLOEXEC: libc::c_uint = libc::O_CLOEXEC as libc::c_uint;
const AT_RECURSIVE: libc::c_uint = 0x8000;
const AT_EMPTY_PATH: libc::c_uint = libc::AT_EMPTY_PATH as libc::c_uint;
const MOVE_MOUNT_F_EMPTY_PATH: libc::c_uint = 0x4;
const MOVE_MOUNT_T_EMPTY_PATH: libc::c_uint = 0x40;
pub(crate) const MOUNT_ATTR_RDONLY: u64 = 0x1;
const MOUNT_ATTR_NOSUID: u64 = 0x2;
const MOUNT_ATTR_NODEV: u64 = 0x4;
pub(crate) const MOUNT_ATTR_NOEXEC: u64 = 0x8;
const FSOPEN_CLOEXEC: libc::c_uint = 0x1;
const FSMOUNT_CLOEXEC: libc::c_uint = 0x1;
const FSCONFIG_SET_STRING: libc::c_uint = 1;
const FSCONFIG_CMD_CREATE: libc::c_uint = 6;
const PRIVATE_SHM_OPTIONS: &CStr = c"mode=1777,size=67108864";
/// Mount attributes shared by every mask mount: they are policy scaffolding,
/// never a place to carry executables, device nodes, or set-ID semantics.
const MASK_MOUNT_ATTRS: u64 = MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV | MOUNT_ATTR_NOEXEC;

/// `struct mount_attr` for `mount_setattr(2)`. Mirrored locally for the same
/// target-coverage reason as the constants above.
#[repr(C)]
struct MountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}

/// A path a mask is installed on, together with the identity it resolved to
/// when the policy was compiled. [`open_target`] refuses to proceed if the two
/// stop agreeing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Target {
    pub(crate) path: CString,
    pub(crate) dev: libc::dev_t,
    pub(crate) ino: libc::ino_t,
}

/// One masking mount, fully described by parent-prepared bytes. Only the
/// operations targeting an entry inside a hiding tmpfs this plan mounts are
/// addressed by bare path, because no such entry exists to pin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MaskOp {
    /// Overmount a denied directory with an empty tmpfs. `mode` carries the
    /// tmpfs's `mode` option (`0`, or `0111` when re-allowed descendants are
    /// attached inside and the tmpfs is sealed read-only afterwards).
    HideDir {
        target: Target,
        mode: CString,
        seal_later: bool,
    },
    /// Overmount a denied regular file with an empty read-only `mode=0` file
    /// created on a detached tmpfs.
    HideFile { target: Target },
    /// Create a traversal-only (`mode=0111`) directory inside a hiding tmpfs
    /// on the way to an attached re-allowed descendant.
    SkeletonDir { path: CString },
    /// Create an empty mount-point file inside a hiding tmpfs for an attached
    /// re-allowed file.
    SkeletonFile { path: CString },
    /// Attach the detached clone `clone_sources[slot]` at `path`.
    Attach { slot: usize, path: CString },
    /// Clone the target subtree and re-attach it over itself with rights
    /// stripped via mount attributes (`MOUNT_ATTR_RDONLY` /
    /// `MOUNT_ATTR_NOEXEC`).
    Restrict {
        target: Target,
        attr_set: u64,
        recursive: bool,
    },
}

/// A compiled masking plan: which subtrees to clone before masking, the
/// depth-ordered mount operations, and which hiding tmpfs mounts to seal
/// read-only after their attachments are in place.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct MountPlan {
    pub(crate) clone_sources: Vec<Target>,
    pub(crate) ops: Vec<MaskOp>,
    pub(crate) seal_readonly: Vec<CString>,
}

impl MountPlan {
    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.clone_sources.is_empty() && self.ops.is_empty() && self.seal_readonly.is_empty()
    }
}

/// Per-spawn state for entering the IPC/user/mount namespaces: the masking
/// plan, uid/gid map lines, and slots for clone descriptors. Built in the
/// parent so `enter` allocates nothing after `fork()`.
pub(crate) struct PreparedNamespace {
    plan: MountPlan,
    uid_map: Vec<u8>,
    gid_map: Vec<u8>,
    clone_fds: Box<[libc::c_int]>,
}

impl PreparedNamespace {
    /// Prepare mandatory namespace entry and the optional masking `plan`.
    pub(crate) fn new(plan: &MountPlan) -> Self {
        let (uid, gid) = current_uid_gid();
        Self {
            plan: plan.clone(),
            uid_map: identity_map(uid),
            gid_map: identity_map(gid),
            clone_fds: vec![-1; plan.clone_sources.len()].into_boxed_slice(),
        }
    }

    /// Enter the fresh namespaces, mount private `/dev/mqueue` and `/dev/shm`,
    /// and install every mask. Called inside `pre_exec` in the freshly forked
    /// child: raw syscalls over parent-built data only. Descriptors opened here
    /// are `O_CLOEXEC` and closed as soon as they are consumed; on error the
    /// failed spawn tears the child down, so no cleanup path is needed.
    pub(crate) fn enter(&mut self) -> io::Result<()> {
        enter_user_mount_ipc_ns(&self.uid_map, &self.gid_map)?;
        mount_private_mqueue()?;
        mount_private_shm()?;

        // Clone every re-exposed subtree before any mask shadows it. The plan
        // pairs each source with a slot, so iterate them in lockstep.
        for (source, slot_fd) in self
            .plan
            .clone_sources
            .iter()
            .zip(self.clone_fds.iter_mut())
        {
            let source_fd = open_target(source)?;
            let cloned = open_tree(
                source_fd,
                c"",
                OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC | AT_EMPTY_PATH | AT_RECURSIVE,
            );
            // SAFETY: source_fd was opened above and is owned here.
            unsafe { libc::close(source_fd) };
            *slot_fd = cloned?;
        }

        for op in &self.plan.ops {
            apply_op(op, &mut self.clone_fds)?;
        }

        // Seal skeleton-bearing tmpfs mounts read-only. Non-recursive: the
        // attached clones on top keep their own (policy-governed) rights.
        for path in &self.plan.seal_readonly {
            mount_setattr_path(path, 0, MOUNT_ATTR_RDONLY)?;
        }

        // Lock the masks: mounts inherited across this second, less
        // privileged user-namespace boundary become MNT_LOCKED, so the child
        // can never unmount them to reveal hidden content — even when policy
        // or euid lets it create namespaces of its own.
        enter_user_mount_ns(&self.uid_map, &self.gid_map)?;
        Ok(())
    }
}

/// Resolve `target` in the child's mount namespace and verify it is still the
/// inode the policy was compiled against. Every later syscall uses the
/// returned descriptor rather than the path, so nothing can change underneath
/// between the check and the mount.
///
/// `EPERM` on a mismatch: the path was redirected after the policy was
/// compiled, and confining the wrong inode would silently drop a deny.
fn open_target(target: &Target) -> io::Result<libc::c_int> {
    // SAFETY: the path is NUL-terminated and owned by the plan; the flags are
    // scalar. O_PATH pins the (mount, dentry) pair without granting access.
    let fd = check_fd(unsafe { libc::open(target.path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) })?;
    // SAFETY: `stat` is a plain C struct; an all-zero value is a valid initial
    // state for `fstat` to overwrite.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: fd was opened above and st is a valid out-pointer.
    let rc = unsafe { libc::fstat(fd, &mut st) };
    let verdict = if rc != 0 {
        Err(io::Error::last_os_error())
    } else if st.st_dev != target.dev || st.st_ino != target.ino {
        Err(io::Error::from_raw_os_error(libc::EPERM))
    } else {
        Ok(fd)
    };
    if verdict.is_err() {
        // SAFETY: fd was opened above and is owned here.
        unsafe { libc::close(fd) };
    }
    verdict
}

/// Mount the fresh IPC namespace's POSIX message-queue filesystem over the
/// inherited host mount. An mqueue mount remains associated with the IPC
/// namespace in which it was created, so `CLONE_NEWIPC` alone does not replace
/// the inherited `/dev/mqueue` view.
fn mount_private_mqueue() -> io::Result<()> {
    // SAFETY: all pointers are NUL-terminated literals, data is unused, and
    // the flags are scalars.
    check_rc(unsafe {
        libc::mount(
            c"guardrail-mqueue".as_ptr(),
            c"/dev/mqueue".as_ptr(),
            c"mqueue".as_ptr(),
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            std::ptr::null(),
        )
    })
}

/// Hide the host's `/dev/shm` behind a per-spawn tmpfs. The fixed 64 MiB cap
/// keeps POSIX shared memory from consuming an unbounded amount of RAM/swap;
/// the mount flags prevent this internal IPC store from carrying executables,
/// device nodes, or set-ID semantics.
fn mount_private_shm() -> io::Result<()> {
    // SAFETY: all pointers are NUL-terminated literals and the flags/data are
    // immutable for the duration of the call.
    check_rc(unsafe {
        libc::mount(
            c"guardrail-shm".as_ptr(),
            c"/dev/shm".as_ptr(),
            c"tmpfs".as_ptr(),
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            PRIVATE_SHM_OPTIONS.as_ptr().cast(),
        )
    })
}

fn apply_op(op: &MaskOp, clone_fds: &mut [libc::c_int]) -> io::Result<()> {
    match op {
        MaskOp::HideDir {
            target,
            mode,
            seal_later,
        } => {
            let mut attrs = MASK_MOUNT_ATTRS;
            if !seal_later {
                attrs |= MOUNT_ATTR_RDONLY;
            }
            with_target(target, |tfd| {
                let mfd = new_tmpfs(mode, attrs)?;
                let result = move_mount_onto(mfd, tfd);
                // SAFETY: mfd was created above and is owned here.
                unsafe { libc::close(mfd) };
                result
            })
        }
        MaskOp::HideFile { target } => with_target(target, hide_file),
        MaskOp::SkeletonDir { path } => {
            // SAFETY: path is a NUL-terminated string owned by the plan.
            let rc = unsafe { libc::mkdir(path.as_ptr(), 0o111) };
            if rc != 0 && last_errno() != libc::EEXIST {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
        MaskOp::SkeletonFile { path } => {
            // SAFETY: path is a NUL-terminated string owned by the plan.
            let fd = unsafe {
                libc::open(
                    path.as_ptr(),
                    libc::O_WRONLY | libc::O_CREAT | libc::O_CLOEXEC,
                    0o000 as libc::c_uint,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: fd was opened above and is owned here.
            unsafe { libc::close(fd) };
            Ok(())
        }
        MaskOp::Attach { slot, path } => {
            // `slot` indexes a fd `enter` cloned for exactly this op; the plan
            // builds them in lockstep, so it is always in range.
            let slot_fd = clone_fds
                .get_mut(*slot)
                .expect("attach slot must index a clone fd");
            let fd = *slot_fd;
            move_mount_fd(fd, path)?;
            // SAFETY: fd was opened by `enter` and is consumed here.
            unsafe { libc::close(fd) };
            *slot_fd = -1;
            Ok(())
        }
        MaskOp::Restrict {
            target,
            attr_set,
            recursive,
        } => {
            let at_recursive = if *recursive { AT_RECURSIVE } else { 0 };
            with_target(target, |tfd| {
                // Clone the target subtree, strip the denied rights while the
                // clone is still detached, and only then attach it over the
                // original — the restricted view is never briefly permissive.
                let otfd = open_tree(
                    tfd,
                    c"",
                    OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC | AT_EMPTY_PATH | at_recursive,
                )?;
                let result = mount_setattr_fd(otfd, at_recursive, *attr_set)
                    .and_then(|()| move_mount_onto(otfd, tfd));
                // SAFETY: otfd was opened above and is owned here.
                unsafe { libc::close(otfd) };
                result
            })
        }
    }
}

/// Resolve and verify `target`, run `f` over the resulting descriptor, and
/// close it either way.
fn with_target<F>(target: &Target, f: F) -> io::Result<()>
where
    F: FnOnce(libc::c_int) -> io::Result<()>,
{
    let tfd = open_target(target)?;
    let result = f(tfd);
    // SAFETY: tfd was opened above and is owned here.
    unsafe { libc::close(tfd) };
    result
}

/// Create a detached tmpfs with the given `mode` option and mount attributes.
/// Returns its mount descriptor, ready for [`move_mount_onto`].
fn new_tmpfs(mode: &CStr, attrs: u64) -> io::Result<libc::c_int> {
    // SAFETY: fsopen takes a NUL-terminated filesystem name and scalar flags.
    let fsfd = check_fd(unsafe {
        libc::syscall(libc::SYS_fsopen, c"tmpfs".as_ptr(), FSOPEN_CLOEXEC) as libc::c_int
    })?;
    let result = configure_and_mount_tmpfs(fsfd, mode, attrs);
    // SAFETY: fsfd was opened above and is owned here.
    unsafe { libc::close(fsfd) };
    result
}

fn configure_and_mount_tmpfs(
    fsfd: libc::c_int,
    mode: &CStr,
    attrs: u64,
) -> io::Result<libc::c_int> {
    // SAFETY: the key and value are NUL-terminated and fsfd is owned by the
    // caller for the duration of the call.
    check_rc(unsafe {
        libc::syscall(
            libc::SYS_fsconfig,
            fsfd,
            FSCONFIG_SET_STRING,
            c"mode".as_ptr(),
            mode.as_ptr(),
            0 as libc::c_int,
        ) as libc::c_int
    })?;
    // SAFETY: FSCONFIG_CMD_CREATE takes no key/value; fsfd is owned by the
    // caller.
    check_rc(unsafe {
        libc::syscall(
            libc::SYS_fsconfig,
            fsfd,
            FSCONFIG_CMD_CREATE,
            std::ptr::null::<libc::c_char>(),
            std::ptr::null::<libc::c_char>(),
            0 as libc::c_int,
        ) as libc::c_int
    })?;
    // SAFETY: fsfd holds a created superblock; scalar flags only.
    check_fd(unsafe {
        libc::syscall(
            libc::SYS_fsmount,
            fsfd,
            FSMOUNT_CLOEXEC,
            attrs as libc::c_uint,
        ) as libc::c_int
    })
}

/// Overmount a denied regular file with an empty read-only `mode=0` file:
/// build a detached tmpfs (`fsopen`/`fsmount`), create the file there, clone
/// it as a detached file mount, strip every right, and move it over the pinned
/// descriptor. No host filesystem path is touched along the way.
fn hide_file(target: libc::c_int) -> io::Result<()> {
    // Writable at first: the placeholder file has to be created before the
    // clone is sealed read-only below.
    let mfd = new_tmpfs(c"0", MASK_MOUNT_ATTRS)?;
    let result = hide_file_onto(mfd, target);
    // SAFETY: mfd was created above and is owned here.
    unsafe { libc::close(mfd) };
    result
}

fn hide_file_onto(mfd: libc::c_int, target: libc::c_int) -> io::Result<()> {
    // SAFETY: mfd is a mount fd usable as a directory fd; the name is a
    // NUL-terminated literal. mode 0 is immune to the inherited umask.
    let ffd = check_fd(unsafe {
        libc::openat(
            mfd,
            c"f".as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
            0o000 as libc::c_uint,
        )
    })?;
    // SAFETY: ffd was opened above and is owned here.
    unsafe { libc::close(ffd) };
    let otfd = open_tree(mfd, c"f", OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC)?;
    // The mount itself goes read-only, so not even the owner can chmod the
    // mode-0 file back open.
    let result = mount_setattr_fd(
        otfd,
        0,
        MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV | MOUNT_ATTR_NOEXEC,
    )
    .and_then(|()| move_mount_onto(otfd, target));
    // SAFETY: otfd was opened above and is owned here.
    unsafe { libc::close(otfd) };
    result
}

/// Enter the first user + mount namespace together with a fresh IPC namespace.
fn enter_user_mount_ipc_ns(uid_map: &[u8], gid_map: &[u8]) -> io::Result<()> {
    enter_namespaces(
        libc::CLONE_NEWUSER | libc::CLONE_NEWNS | libc::CLONE_NEWIPC,
        uid_map,
        gid_map,
    )
}

/// Enter the second user + mount namespace that locks the installed mounts.
fn enter_user_mount_ns(uid_map: &[u8], gid_map: &[u8]) -> io::Result<()> {
    enter_namespaces(libc::CLONE_NEWUSER | libc::CLONE_NEWNS, uid_map, gid_map)
}

/// Enter `flags`, map the current euid/egid onto themselves, and stop mount
/// propagation to the host. Requires a single-threaded post-`fork` caller.
fn enter_namespaces(flags: libc::c_int, uid_map: &[u8], gid_map: &[u8]) -> io::Result<()> {
    // SAFETY: unshare takes only a scalar flags argument.
    check_rc(unsafe { libc::unshare(flags) })?;
    // An unprivileged process may write exactly one mapping line for its own
    // euid/egid; gid_map requires setgroups to be denied first.
    write_file(c"/proc/self/setgroups", b"deny")?;
    write_file(c"/proc/self/gid_map", gid_map)?;
    write_file(c"/proc/self/uid_map", uid_map)?;
    // SAFETY: the target is a NUL-terminated literal; source/fstype/data are
    // unused for propagation changes.
    check_rc(unsafe {
        libc::mount(
            std::ptr::null(),
            c"/".as_ptr(),
            std::ptr::null(),
            libc::MS_SLAVE | libc::MS_REC,
            std::ptr::null(),
        )
    })
}

/// Verify the mandatory per-spawn IPC/user/mount namespaces and private IPC
/// mounts. Runs the exact empty-plan setup in a disposable forked child so the
/// caller's process state is untouched.
pub(crate) fn probe_namespace_support() -> Result<()> {
    let mut namespace = PreparedNamespace::new(&MountPlan::default());

    // SAFETY: fork takes no arguments; the child below only calls
    // async-signal-safe functions (unshare, open, write, close, mount,
    // _exit) before exiting.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(Error::confinement(
            "namespace isolation probe",
            io::Error::last_os_error(),
        ));
    }
    if pid == 0 {
        let code = match namespace.enter() {
            Ok(()) => 0,
            Err(err) => err.raw_os_error().unwrap_or(libc::EIO),
        };
        // SAFETY: immediate exit without running any Rust cleanup.
        unsafe { libc::_exit(code) };
    }

    let mut status: libc::c_int = 0;
    loop {
        // SAFETY: status is a valid out-pointer; pid is our direct child.
        let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
        if rc == pid {
            break;
        }
        if rc < 0 && last_errno() != libc::EINTR {
            return Err(Error::confinement(
                "namespace isolation probe",
                io::Error::last_os_error(),
            ));
        }
    }

    if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
        return Ok(());
    }
    let detail = if libc::WIFEXITED(status) {
        io::Error::from_raw_os_error(libc::WEXITSTATUS(status)).to_string()
    } else {
        "probe child terminated abnormally".into()
    };
    Err(Error::Unsupported(format!(
        "the Linux backend requires a fresh IPC namespace with private \
         /dev/mqueue and /dev/shm mounts inside unprivileged user and mount \
         namespaces for every sandbox; creating them failed: {detail}. Enable \
         unprivileged user \
         namespaces (Debian: sysctl kernel.unprivileged_userns_clone=1; \
         Ubuntu 24.04+: sysctl kernel.apparmor_restrict_unprivileged_userns=0; \
         also check user.max_user_namespaces)"
    )))
}

/// `"<id> <id> 1\n"` — the single identity-mapping line an unprivileged
/// process may install for itself.
fn identity_map(id: u64) -> Vec<u8> {
    format!("{id} {id} 1\n").into_bytes()
}

/// The caller's effective uid/gid, widened to `u64` for the identity map.
fn current_uid_gid() -> (u64, u64) {
    // SAFETY: geteuid takes no arguments and returns the effective uid.
    let uid = unsafe { libc::geteuid() } as u64;
    // SAFETY: getegid takes no arguments and returns the effective gid.
    let gid = unsafe { libc::getegid() } as u64;
    (uid, gid)
}

/// Open `path` write-only and write `buf` in one call (uid/gid map and
/// setgroups writes are all-or-nothing).
fn write_file(path: &CStr, buf: &[u8]) -> io::Result<()> {
    // SAFETY: path is NUL-terminated; flags are scalar.
    let fd = check_fd(unsafe { libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) })?;
    // SAFETY: buf is a valid readable buffer of the given length.
    let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
    let err = if n == buf.len() as isize {
        None
    } else if n < 0 {
        Some(io::Error::last_os_error())
    } else {
        Some(io::Error::from_raw_os_error(libc::EIO))
    };
    // SAFETY: fd was opened above and is owned here.
    unsafe { libc::close(fd) };
    err.map_or(Ok(()), Err)
}

fn open_tree(dfd: libc::c_int, path: &CStr, flags: libc::c_uint) -> io::Result<libc::c_int> {
    // SAFETY: path is NUL-terminated; the remaining args are scalars.
    check_fd(unsafe {
        libc::syscall(libc::SYS_open_tree, dfd, path.as_ptr(), flags) as libc::c_int
    })
}

/// Attach the detached mount `fd` at `to`.
fn move_mount_fd(fd: libc::c_int, to: &CStr) -> io::Result<()> {
    // SAFETY: the empty-path literal and `to` are NUL-terminated; fd is a
    // detached mount owned by the caller.
    check_rc(unsafe {
        libc::syscall(
            libc::SYS_move_mount,
            fd,
            c"".as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            MOVE_MOUNT_F_EMPTY_PATH,
        ) as libc::c_int
    })
}

/// Attach the detached mount `fd` directly onto the pinned descriptor `to`,
/// naming neither end by path.
fn move_mount_onto(fd: libc::c_int, to: libc::c_int) -> io::Result<()> {
    // SAFETY: both empty-path literals are NUL-terminated; `fd` is a detached
    // mount and `to` an `O_PATH` descriptor, both owned by the caller.
    check_rc(unsafe {
        libc::syscall(
            libc::SYS_move_mount,
            fd,
            c"".as_ptr(),
            to,
            c"".as_ptr(),
            MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH,
        ) as libc::c_int
    })
}

fn mount_setattr_path(path: &CStr, flags: libc::c_uint, attr_set: u64) -> io::Result<()> {
    let attr = MountAttr {
        attr_set,
        attr_clr: 0,
        propagation: 0,
        userns_fd: 0,
    };
    // SAFETY: path is NUL-terminated and attr is a valid struct of the size
    // passed; only the listed attributes are set, none cleared.
    check_rc(unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            libc::AT_FDCWD,
            path.as_ptr(),
            flags,
            &attr,
            std::mem::size_of::<MountAttr>(),
        ) as libc::c_int
    })
}

fn mount_setattr_fd(fd: libc::c_int, flags: libc::c_uint, attr_set: u64) -> io::Result<()> {
    let attr = MountAttr {
        attr_set,
        attr_clr: 0,
        propagation: 0,
        userns_fd: 0,
    };
    // SAFETY: the empty-path literal is NUL-terminated, fd is owned by the
    // caller, and attr is a valid struct of the size passed.
    check_rc(unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            fd,
            c"".as_ptr(),
            AT_EMPTY_PATH | flags,
            &attr,
            std::mem::size_of::<MountAttr>(),
        ) as libc::c_int
    })
}

fn check_rc(rc: libc::c_int) -> io::Result<()> {
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn check_fd(fd: libc::c_int) -> io::Result<libc::c_int> {
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

fn last_errno() -> libc::c_int {
    io::Error::last_os_error().raw_os_error().unwrap_or(0)
}
