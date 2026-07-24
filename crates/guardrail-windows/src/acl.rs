//! Persistent filesystem ACL application for the sandbox principals.
//!
//! ACEs are durable host state, deliberately **not** removed when a sandbox is
//! dropped: an app restart with an unchanged policy must not re-propagate
//! inheritable ACEs over a large tree. The per-namespace manifest
//! ([`crate::manifest`]) records what was last applied; on the next run the
//! policy is either verified in place (unchanged), applied as a set-diff of
//! canonical ACE operations (changed), or rebuilt from scratch (manifest
//! missing/corrupt, or on-disk state at a touched root no longer matching —
//! "self-heal"). [`crate::cache::cleanup_namespace`] removes everything when a
//! namespace is retired.

#![cfg(windows)]

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::io;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::ptr;
use std::slice;
use std::sync::{Mutex, OnceLock};

use guardrail_core::{Error, FsAccess, Result, WindowsAclVerification};
use windows_sys::Win32::Foundation::{ERROR_SUCCESS, HLOCAL, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ACCESS_MODE, DENY_ACCESS, EXPLICIT_ACCESS_W, GRANT_ACCESS, GetNamedSecurityInfoW,
    SE_FILE_OBJECT, SetEntriesInAclW, SetNamedSecurityInfoW, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN,
    TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, AddAce, CONTAINER_INHERIT_ACE, CopySid,
    DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetLengthSid, GetSecurityDescriptorControl,
    INHERITED_ACE, InitializeAcl, OBJECT_INHERIT_ACE, PSID, SE_DACL_PROTECTED,
};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_APPEND_DATA, FILE_ATTRIBUTE_REPARSE_POINT, FILE_EXECUTE, FILE_GENERIC_EXECUTE,
    FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_READ_EA,
    FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA,
};
use windows_sys::core::PWSTR;

static ACL_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const ACCESS_DENIED_ACE_TYPE: u8 = 1;

/// The sandbox principals' SIDs, in application order.
pub(crate) struct Principals {
    pub(crate) package_sid: Vec<u8>,
    pub(crate) filesystem_sid: Vec<u8>,
    pub(crate) reallow_sid: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Principal {
    Package,
    Filesystem,
    Reallow,
}

impl Principals {
    pub(crate) fn new(
        package_sid: PSID,
        filesystem_sid: PSID,
        reallow_sid: PSID,
    ) -> io::Result<Self> {
        Ok(Self {
            package_sid: copy_sid(package_sid)?,
            filesystem_sid: copy_sid(filesystem_sid)?,
            reallow_sid: copy_sid(reallow_sid)?,
        })
    }

    fn sid(&self, principal: Principal) -> PSID {
        match principal {
            Principal::Package => self.package_sid.as_ptr().cast_mut().cast(),
            Principal::Filesystem => self.filesystem_sid.as_ptr().cast_mut().cast(),
            Principal::Reallow => self.reallow_sid.as_ptr().cast_mut().cast(),
        }
    }

    fn principal_of(&self, sid: PSID) -> Option<Principal> {
        for principal in [Principal::Package, Principal::Filesystem, Principal::Reallow] {
            if unsafe { EqualSid(self.sid(principal), sid) } != 0 {
                return Some(principal);
            }
        }
        None
    }
}

/// One explicit guardrail ACE on one root: the unit of diffing.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Op {
    path: PathBuf,
    principal: Principal,
    deny: bool,
    mask: u32,
}

/// Compile the canonical operation set for a rule list. Allow rules grant the
/// package SID; deny rules deny the filesystem SID; an allow beneath a
/// same-right deny ancestor additionally grants the denied bits to the
/// re-allow SID — explicit ACEs precede inherited ACEs in canonical DACL
/// order, so that grant is consumed before the ancestor's inherited deny can
/// veto.
fn ops(entries: &[Rule]) -> BTreeSet<Op> {
    let mut set = BTreeSet::new();
    for entry in entries {
        match entry.effect {
            RuleEffect::Allow => {
                set.insert(Op {
                    path: entry.path.clone(),
                    principal: Principal::Package,
                    deny: false,
                    mask: allow_mask(entry.right),
                });
                if shadowed_by_deny(entries, entry) {
                    set.insert(Op {
                        path: entry.path.clone(),
                        principal: Principal::Reallow,
                        deny: false,
                        mask: deny_mask(entry.right),
                    });
                }
            }
            RuleEffect::Deny => {
                set.insert(Op {
                    path: entry.path.clone(),
                    principal: Principal::Filesystem,
                    deny: true,
                    mask: deny_mask(entry.right),
                });
            }
        }
    }
    set
}

/// Canonicalize a rule list into its ordered final-effect entries. Public to
/// the crate so the cache can compare a new policy against the manifest before
/// acquiring the namespace.
pub(crate) fn canonical_rules(fs: &[FsAccess]) -> Result<Vec<Rule>> {
    compile_entries(fs).map_err(|err| Error::confinement("acl", err))
}

/// Marker owned by the cache proving the namespace's ACEs are applied. ACEs
/// are persistent host state — nothing is stripped on drop.
#[derive(Debug)]
pub(crate) struct AclGuard(());

impl AclGuard {
    /// Bring on-disk ACL state in line with `entries`, using `previous` (the
    /// loaded manifest) to decide between verify, set-diff, and full rebuild.
    /// Returns the guard; the caller persists the manifest afterwards.
    pub(crate) fn apply(
        entries: &[Rule],
        previous: Option<&[Rule]>,
        principals: &Principals,
        verification: WindowsAclVerification,
    ) -> Result<Self> {
        Self::apply_inner(entries, previous, principals, verification)
            .map_err(|err| Error::confinement("acl", err))?;

        // Tools stat or traverse every ancestor of their working directory
        // (git repo discovery, cmd's dir/del), and directories outside the
        // granted trees carry no package ACEs. Stamp sticky non-inheritable
        // traverse grants on each allow root's ancestors, best-effort: the
        // user-owned chain succeeds; system roots (drive roots, C:\Users)
        // need the elevated `guardrail-host-setup` run and are skipped here.
        // The grants target a Windows-defined group SID, are idempotent, and
        // are deliberately never removed.
        for entry in entries {
            if entry.effect != RuleEffect::Allow {
                continue;
            }
            for ancestor in entry.path.ancestors().skip(1) {
                let _ = crate::host::grant_traverse(ancestor);
            }
        }

        Ok(Self(()))
    }

    fn apply_inner(
        entries: &[Rule],
        previous: Option<&[Rule]>,
        principals: &Principals,
        verification: WindowsAclVerification,
    ) -> io::Result<()> {
        let new_ops = ops(entries);
        let Some(previous) = previous else {
            return rebuild(&[], entries, &new_ops, principals);
        };

        if previous == entries {
            return if verified(entries, &new_ops, principals, verification)? {
                Ok(())
            } else {
                // Self-heal: a rule root was replaced (checkout, atomic save)
                // and shed its ACEs. Rebuild the namespace from scratch.
                rebuild(previous, entries, &new_ops, principals)
            };
        }

        let old_ops = ops(previous);
        let removed: Vec<&Op> = old_ops.difference(&new_ops).collect();
        let added: Vec<&Op> = new_ops.difference(&old_ops).collect();

        // Consistency gate: every touched root must still carry exactly the
        // guardrail ACEs the manifest says it does; otherwise the recorded
        // state is stale and the whole namespace is rebuilt.
        let touched: BTreeSet<&Path> = removed
            .iter()
            .chain(added.iter())
            .map(|op| op.path.as_path())
            .collect();
        for path in touched {
            let expected: BTreeSet<Op> = old_ops
                .iter()
                .filter(|op| op.path == path)
                .cloned()
                .collect();
            if read_guardrail_ops(path, principals)? != Some(expected) {
                return rebuild(previous, entries, &new_ops, principals);
            }
        }

        for entry in entries {
            if entry.effect == RuleEffect::Deny
                && added.iter().any(|op| op.path == entry.path && op.deny)
            {
                validate_deny_tree(&entry.path)?;
            }
        }
        for op in removed {
            remove_acl_entry(&op.path, principals.sid(op.principal), op.deny, op.mask)?;
        }
        for op in added {
            apply_op(op, principals)?;
        }
        Ok(())
    }
}

/// Full application: strip every guardrail ACE at the old roots, then apply
/// every new operation.
fn rebuild(
    previous: &[Rule],
    entries: &[Rule],
    new_ops: &BTreeSet<Op>,
    principals: &Principals,
) -> io::Result<()> {
    let old_roots: BTreeSet<&Path> = previous.iter().map(|rule| rule.path.as_path()).collect();
    for path in old_roots {
        for principal in [Principal::Package, Principal::Filesystem, Principal::Reallow] {
            match remove_acl_entries(path, principals.sid(principal)) {
                Ok(()) => {}
                // The root may have been deleted since; nothing to strip.
                Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                Err(err) => return Err(err),
            }
        }
    }
    for entry in entries {
        if entry.effect == RuleEffect::Deny {
            validate_deny_tree(&entry.path)?;
        }
    }
    for op in new_ops {
        apply_op(op, principals)?;
    }
    Ok(())
}

fn apply_op(op: &Op, principals: &Principals) -> io::Result<()> {
    let mode = if op.deny { DENY_ACCESS } else { GRANT_ACCESS };
    add_acl_entry(&op.path, principals.sid(op.principal), mode, op.mask)
}

/// Whether the roots selected by `verification` still carry exactly the
/// expected guardrail ACEs.
fn verified(
    entries: &[Rule],
    expected_ops: &BTreeSet<Op>,
    principals: &Principals,
    verification: WindowsAclVerification,
) -> io::Result<bool> {
    let roots: BTreeSet<&Path> = entries
        .iter()
        .filter(|entry| match verification {
            WindowsAclVerification::None => false,
            WindowsAclVerification::DenyRoots => entry.effect == RuleEffect::Deny,
            WindowsAclVerification::AllRoots => true,
        })
        .map(|entry| entry.path.as_path())
        .collect();
    for path in roots {
        let expected: BTreeSet<Op> = expected_ops
            .iter()
            .filter(|op| op.path == path)
            .cloned()
            .collect();
        if read_guardrail_ops(path, principals)? != Some(expected) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// The explicit guardrail-principal ACEs currently present on `path`, or
/// `None` when the path no longer exists.
fn read_guardrail_ops(path: &Path, principals: &Principals) -> io::Result<Option<BTreeSet<Op>>> {
    let dacl = match Dacl::read(path) {
        Ok(dacl) => dacl,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    };
    if dacl.acl.is_null() {
        return Ok(Some(BTreeSet::new()));
    }
    let acl = unsafe { &*dacl.acl };
    let mut set = BTreeSet::new();
    for index in 0..u32::from(acl.AceCount) {
        let mut ace = ptr::null_mut();
        win32_bool(unsafe { GetAce(dacl.acl, index, &mut ace) })?;
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        if u32::from(header.AceFlags) & INHERITED_ACE != 0
            || (header.AceType != ACCESS_ALLOWED_ACE_TYPE
                && header.AceType != ACCESS_DENIED_ACE_TYPE)
        {
            continue;
        }
        // ACCESS_DENIED_ACE has the same layout as ACCESS_ALLOWED_ACE.
        let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
        let ace_sid: PSID = unsafe {
            ptr::addr_of!((*ace.cast::<ACCESS_ALLOWED_ACE>()).SidStart)
                .cast_mut()
                .cast()
        };
        if let Some(principal) = principals.principal_of(ace_sid) {
            set.insert(Op {
                path: path.to_path_buf(),
                principal,
                deny: header.AceType == ACCESS_DENIED_ACE_TYPE,
                mask: allowed.Mask,
            });
        }
    }
    Ok(Some(set))
}

fn add_acl_entry(path: &Path, sid: PSID, mode: ACCESS_MODE, rights: u32) -> io::Result<()> {
    let lock = ACL_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = lock.lock().unwrap_or_else(|err| err.into_inner());
    add_acl_entry_locked(path, sid, mode, rights)
}

fn add_acl_entry_locked(path: &Path, sid: PSID, mode: ACCESS_MODE, rights: u32) -> io::Result<()> {
    let current = Dacl::read(path)?;
    if current.acl.is_null() {
        return Err(io::Error::other(format!(
            "cannot safely modify the null DACL on {}",
            path.display()
        )));
    }

    let explicit = explicit_access(sid, mode, rights);
    let mut new_acl = ptr::null_mut();
    let status = unsafe { SetEntriesInAclW(1, &explicit, current.acl, &mut new_acl) };
    win32_status(status)?;
    let new_acl = LocalAcl(new_acl);
    set_dacl(path, new_acl.0)
}

/// Remove the single explicit ACE matching `(sid, deny, mask)` from `path`.
fn remove_acl_entry(path: &Path, sid: PSID, deny: bool, mask: u32) -> io::Result<()> {
    let expected_type = if deny {
        ACCESS_DENIED_ACE_TYPE
    } else {
        ACCESS_ALLOWED_ACE_TYPE
    };
    remove_matching_aces(path, |ace| {
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        header.AceType == expected_type
            && unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() }.Mask == mask
            && explicit_standard_ace_matches_sid(ace, sid)
    })
}

/// Remove every explicit ACE for `sid` from `path` (namespace cleanup and
/// rebuild).
pub(crate) fn remove_acl_entries(path: &Path, sid: PSID) -> io::Result<()> {
    remove_matching_aces(path, |ace| explicit_standard_ace_matches_sid(ace, sid))
}

fn remove_matching_aces(
    path: &Path,
    matches: impl Fn(*mut core::ffi::c_void) -> bool,
) -> io::Result<()> {
    let lock = ACL_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = lock.lock().unwrap_or_else(|err| err.into_inner());
    let current = Dacl::read(path)?;
    if current.acl.is_null() {
        return Err(io::Error::other(format!(
            "cannot safely modify the null DACL on {}",
            path.display()
        )));
    }
    let acl = acl_without_matching(current.acl, &matches)?;
    set_dacl(path, acl.as_ptr().cast_mut().cast())
}

fn set_dacl(path: &Path, dacl: *mut ACL) -> io::Result<()> {
    let path_wide = wide_null(path.as_os_str());
    // SetNamedSecurityInfoW automatically propagates inheritable ACE changes
    // to existing children. Future children inherit the same ACE normally.
    let status = unsafe {
        SetNamedSecurityInfoW(
            path_wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            dacl,
            ptr::null_mut(),
        )
    };
    win32_status(status)
}

fn acl_without_matching(
    dacl: *mut ACL,
    matches: &impl Fn(*mut core::ffi::c_void) -> bool,
) -> io::Result<Vec<u32>> {
    // Removal only touches guardrail-owned explicit ACEs, so every unrelated
    // ACE is carried over byte-for-byte unchanged.
    let dacl = unsafe { &*dacl };
    let revision = u32::from(dacl.AclRevision);
    let words = (dacl.AclSize as usize).div_ceil(size_of::<u32>());
    let mut storage = vec![0u32; words];
    let storage_bytes = storage.len() * size_of::<u32>();
    let initialized =
        unsafe { InitializeAcl(storage.as_mut_ptr().cast(), storage_bytes as u32, revision) };
    win32_bool(initialized)?;

    for index in 0..u32::from(dacl.AceCount) {
        let mut ace = ptr::null_mut();
        let got = unsafe { GetAce(ptr::from_ref(dacl).cast_mut(), index, &mut ace) };
        win32_bool(got)?;
        if matches(ace) {
            continue;
        }

        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        let bytes = unsafe { slice::from_raw_parts(ace.cast::<u8>(), header.AceSize as usize) };
        let added = unsafe {
            AddAce(
                storage.as_mut_ptr().cast(),
                revision,
                u32::MAX,
                bytes.as_ptr().cast(),
                bytes.len() as u32,
            )
        };
        win32_bool(added)?;
    }
    Ok(storage)
}

fn explicit_standard_ace_matches_sid(ace: *mut core::ffi::c_void, sid: PSID) -> bool {
    let header = unsafe { &*ace.cast::<ACE_HEADER>() };
    if u32::from(header.AceFlags) & INHERITED_ACE != 0
        || (header.AceType != ACCESS_ALLOWED_ACE_TYPE && header.AceType != ACCESS_DENIED_ACE_TYPE)
    {
        return false;
    }

    let ace = ace.cast::<ACCESS_ALLOWED_ACE>();
    let ace_sid = unsafe { ptr::addr_of!((*ace).SidStart).cast_mut().cast() };
    unsafe { EqualSid(ace_sid, sid) != 0 }
}

struct Dacl {
    acl: *mut ACL,
    descriptor: windows_sys::Win32::Security::PSECURITY_DESCRIPTOR,
}

impl Dacl {
    fn read(path: &Path) -> io::Result<Self> {
        let path_wide = wide_null(path.as_os_str());
        let mut acl = ptr::null_mut();
        let mut descriptor = ptr::null_mut();
        let status = unsafe {
            GetNamedSecurityInfoW(
                path_wide.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut acl,
                ptr::null_mut(),
                &mut descriptor,
            )
        };
        win32_status(status)?;
        Ok(Self { acl, descriptor })
    }

    fn is_protected(&self) -> io::Result<bool> {
        let mut control = 0u16;
        let mut revision = 0u32;
        let ok =
            unsafe { GetSecurityDescriptorControl(self.descriptor, &mut control, &mut revision) };
        win32_bool(ok)?;
        Ok(control & SE_DACL_PROTECTED != 0)
    }
}

impl Drop for Dacl {
    fn drop(&mut self) {
        if !self.descriptor.is_null() {
            unsafe {
                LocalFree(self.descriptor.cast::<core::ffi::c_void>() as HLOCAL);
            }
        }
    }
}

fn validate_deny_tree(root: &Path) -> io::Result<()> {
    let mut pending = vec![(root.to_owned(), true)];
    while let Some((path, is_root)) = pending.pop() {
        let metadata = std::fs::symlink_metadata(&path)?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Windows filesystem deny tree contains a reparse point: {}",
                    path.display()
                ),
            ));
        }

        let dacl = Dacl::read(&path)?;
        if dacl.acl.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Windows filesystem deny tree contains a null DACL: {}",
                    path.display()
                ),
            ));
        }
        if !is_root && dacl.is_protected()? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Windows filesystem deny tree contains a protected DACL: {}",
                    path.display()
                ),
            ));
        }

        if metadata.is_dir() {
            for child in std::fs::read_dir(&path)? {
                pending.push((child?.path(), false));
            }
        }
    }
    Ok(())
}

struct LocalAcl(*mut ACL);

impl Drop for LocalAcl {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0.cast::<core::ffi::c_void>() as HLOCAL);
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FsRight {
    Read,
    Write,
    Execute,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuleEffect {
    Allow,
    Deny,
}

/// One canonical final-effect rule: the manifest and diff unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Rule {
    pub(crate) path: PathBuf,
    pub(crate) right: FsRight,
    pub(crate) effect: RuleEffect,
}

fn compile_entries(fs: &[FsAccess]) -> io::Result<Vec<Rule>> {
    let rules = normalize_rules(fs)?;
    let mut entries = Vec::new();

    for rule in &rules {
        if final_effect(&rules, rule.right, &rule.path) == rule.effect
            && !entries.iter().any(|entry: &Rule| entry == rule)
        {
            entries.push(rule.clone());
        }
    }

    Ok(entries)
}

/// Whether an inherited guardrail deny for the same right reaches this allow
/// root from a strict ancestor. Such an allow needs an explicit re-allow grant
/// so the inherited deny never fires for the granted bits.
fn shadowed_by_deny(entries: &[Rule], allow: &Rule) -> bool {
    entries.iter().any(|entry| {
        entry.effect == RuleEffect::Deny
            && entry.right == allow.right
            && allow.path != entry.path
            && allow.path.starts_with(&entry.path)
    })
}

fn normalize_rules(fs: &[FsAccess]) -> io::Result<Vec<Rule>> {
    fs.iter()
        .map(|rule| {
            let (path, right, effect) = split_rule(rule);
            if effect == RuleEffect::Deny {
                validate_no_reparse_components(path)?;
            }
            Ok(Rule {
                path: std::fs::canonicalize(path)?,
                right,
                effect,
            })
        })
        .collect()
}

fn validate_no_reparse_components(path: &Path) -> io::Result<()> {
    let mut current = PathBuf::new();
    for component in std::path::absolute(path)?.components() {
        current.push(component);
        if !current.is_absolute() {
            continue;
        }
        let metadata = std::fs::symlink_metadata(&current)?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Windows filesystem deny path crosses a reparse point: {}",
                    current.display()
                ),
            ));
        }
    }
    Ok(())
}

fn final_effect(rules: &[Rule], right: FsRight, path: &Path) -> RuleEffect {
    let mut effect = RuleEffect::Deny;
    for rule in rules {
        if rule.right == right && path.starts_with(&rule.path) {
            effect = rule.effect;
        }
    }
    effect
}

fn split_rule(rule: &FsAccess) -> (&Path, FsRight, RuleEffect) {
    match rule {
        FsAccess::ReadAllow(path) => (path, FsRight::Read, RuleEffect::Allow),
        FsAccess::ReadDeny(path) => (path, FsRight::Read, RuleEffect::Deny),
        FsAccess::WriteAllow(path) => (path, FsRight::Write, RuleEffect::Allow),
        FsAccess::WriteDeny(path) => (path, FsRight::Write, RuleEffect::Deny),
        FsAccess::ExecuteAllow(path) => (path, FsRight::Execute, RuleEffect::Allow),
        FsAccess::ExecuteDeny(path) => (path, FsRight::Execute, RuleEffect::Deny),
    }
}

fn allow_mask(right: FsRight) -> u32 {
    match right {
        FsRight::Read => FILE_GENERIC_READ,
        // DELETE makes write grants cover deletion and renaming.
        // FILE_DELETE_CHILD is never granted: it would let the child remove
        // write-denied entries through their parent directory.
        // FILE_READ_ATTRIBUTES rides along because kernel32 file opens
        // (CreateFileW, MoveFileExW) implicitly request it, so a write grant
        // without it cannot open existing files at all. It exposes metadata
        // only, exactly as FILE_GENERIC_EXECUTE already does.
        FsRight::Write => FILE_GENERIC_WRITE | DELETE | FILE_READ_ATTRIBUTES,
        FsRight::Execute => FILE_GENERIC_EXECUTE,
    }
}

fn deny_mask(right: FsRight) -> u32 {
    match right {
        FsRight::Read => FILE_READ_DATA | FILE_READ_EA | FILE_READ_ATTRIBUTES,
        FsRight::Write => {
            FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | DELETE
        }
        FsRight::Execute => FILE_EXECUTE,
    }
}

fn explicit_access(sid: PSID, mode: ACCESS_MODE, rights: u32) -> EXPLICIT_ACCESS_W {
    EXPLICIT_ACCESS_W {
        grfAccessPermissions: rights,
        grfAccessMode: mode,
        grfInheritance: OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: ptr::null_mut(),
            MultipleTrusteeOperation: 0,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_UNKNOWN,
            ptstrName: sid.cast::<u16>() as PWSTR,
        },
    }
}

fn copy_sid(sid: PSID) -> io::Result<Vec<u8>> {
    let len = unsafe { GetLengthSid(sid) };
    if len == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut storage = vec![0u8; len as usize];
    let copied = unsafe { CopySid(len, storage.as_mut_ptr().cast(), sid) };
    win32_bool(copied)?;
    Ok(storage)
}

fn wide_null(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

fn win32_status(status: u32) -> io::Result<()> {
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(status as i32))
    }
}

fn win32_bool(ok: i32) -> io::Result<()> {
    if ok != 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_APPEND_DATA, FILE_EXECUTE, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_READ_EA,
        FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA, READ_CONTROL, SYNCHRONIZE,
    };

    #[test]
    fn rights_are_independent() {
        assert_eq!(allow_mask(FsRight::Read), FILE_GENERIC_READ);
        assert_eq!(
            file_specific_rights(allow_mask(FsRight::Read)),
            FILE_READ_DATA | FILE_READ_EA | FILE_READ_ATTRIBUTES
        );
        assert_eq!(
            allow_mask(FsRight::Write),
            FILE_GENERIC_WRITE | DELETE | FILE_READ_ATTRIBUTES
        );
        assert_eq!(
            file_specific_rights(allow_mask(FsRight::Write)),
            FILE_WRITE_DATA
                | FILE_APPEND_DATA
                | FILE_WRITE_EA
                | FILE_WRITE_ATTRIBUTES
                | DELETE
                | FILE_READ_ATTRIBUTES
        );
        assert_eq!(
            deny_mask(FsRight::Write),
            FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | DELETE
        );
        assert_eq!(allow_mask(FsRight::Execute), FILE_GENERIC_EXECUTE);
        assert_eq!(
            file_specific_rights(allow_mask(FsRight::Execute)),
            FILE_EXECUTE | FILE_READ_ATTRIBUTES
        );
    }

    #[test]
    fn allow_and_deny_target_different_principals() {
        let sid = 1usize as PSID;
        let allow = explicit_access(sid, GRANT_ACCESS, allow_mask(FsRight::Read));
        let deny = explicit_access(sid, DENY_ACCESS, deny_mask(FsRight::Read));

        assert_eq!(allow.grfAccessMode, GRANT_ACCESS);
        assert_eq!(deny.grfAccessMode, DENY_ACCESS);
        assert_eq!(allow.Trustee.ptstrName as usize, sid as usize);
        assert_eq!(deny.Trustee.ptstrName as usize, sid as usize);
        assert_eq!(
            allow.grfInheritance,
            OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
        );
        assert_eq!(deny.grfInheritance, allow.grfInheritance);
    }

    #[test]
    fn compiler_keeps_parent_allow_and_child_deny() {
        let root = temp_dir("allow-deny");
        let child = root.join("child");
        std::fs::create_dir(&child).unwrap();
        let root_canonical = std::fs::canonicalize(&root).unwrap();
        let child_canonical = std::fs::canonicalize(&child).unwrap();

        let entries =
            compile_entries(&[FsAccess::ReadAllow(root.clone()), FsAccess::ReadDeny(child)])
                .unwrap();

        assert_eq!(
            entries,
            vec![
                Rule {
                    path: root_canonical,
                    right: FsRight::Read,
                    effect: RuleEffect::Allow,
                },
                Rule {
                    path: child_canonical,
                    right: FsRight::Read,
                    effect: RuleEffect::Deny,
                },
            ]
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn compiler_keeps_nested_reallow_and_marks_the_shadow() {
        let root = temp_dir("nested-reallow");
        let child = root.join("child");
        std::fs::create_dir(&child).unwrap();
        let root_canonical = std::fs::canonicalize(&root).unwrap();
        let child_canonical = std::fs::canonicalize(&child).unwrap();

        let entries =
            compile_entries(&[FsAccess::ReadDeny(root.clone()), FsAccess::ReadAllow(child)])
                .unwrap();

        assert_eq!(
            entries,
            vec![
                Rule {
                    path: root_canonical,
                    right: FsRight::Read,
                    effect: RuleEffect::Deny,
                },
                Rule {
                    path: child_canonical,
                    right: FsRight::Read,
                    effect: RuleEffect::Allow,
                },
            ]
        );
        assert!(shadowed_by_deny(&entries, &entries[1]));
        assert!(!shadowed_by_deny(&entries, &entries[0]));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn compiler_obeys_later_same_path_rule() {
        let root = temp_dir("same-path");
        let canonical = std::fs::canonicalize(&root).unwrap();

        let entries = compile_entries(&[
            FsAccess::ReadAllow(root.clone()),
            FsAccess::ReadDeny(root.clone()),
            FsAccess::ReadAllow(root.clone()),
        ])
        .unwrap();

        assert_eq!(
            entries,
            vec![Rule {
                path: canonical,
                right: FsRight::Read,
                effect: RuleEffect::Allow,
            }]
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn compiler_drops_child_deny_overridden_by_later_parent_allow() {
        let root = temp_dir("overridden-child");
        let child = root.join("child");
        std::fs::create_dir(&child).unwrap();
        let canonical = std::fs::canonicalize(&root).unwrap();

        let entries = compile_entries(&[
            FsAccess::ReadAllow(root.clone()),
            FsAccess::ReadDeny(child),
            FsAccess::ReadAllow(root.clone()),
        ])
        .unwrap();

        assert_eq!(
            entries,
            vec![Rule {
                path: canonical,
                right: FsRight::Read,
                effect: RuleEffect::Allow,
            }]
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn nested_rules_for_independent_rights_are_supported() {
        let root = temp_dir("independent-rights");
        let child = root.join("child");
        std::fs::create_dir(&child).unwrap();

        let entries = compile_entries(&[
            FsAccess::ReadDeny(root.clone()),
            FsAccess::WriteAllow(child),
        ])
        .unwrap();

        assert_eq!(entries.len(), 2);
        let _ = std::fs::remove_dir_all(root);
    }

    fn file_specific_rights(rights: u32) -> u32 {
        rights & !(READ_CONTROL | SYNCHRONIZE)
    }

    fn temp_dir(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "guardrail-acl-{label}-{}-{}",
            std::process::id(),
            unique_suffix()
        ));
        std::fs::create_dir(&path).unwrap();
        path
    }

    fn unique_suffix() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    }
}
