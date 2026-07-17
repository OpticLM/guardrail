//! Temporary filesystem ACL rules for the AppContainer SID.

#![cfg(windows)]

use std::ffi::OsStr;
use std::io;
use std::mem;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;
use std::slice;

use guardrail_core::{Error, FsAccess, Result};
use windows_sys::Win32::Foundation::{ERROR_SUCCESS, HLOCAL, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    EXPLICIT_ACCESS_W, GRANT_ACCESS, SE_FILE_OBJECT, SetEntriesInAclW, SetNamedSecurityInfoW,
    TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_REVISION, AddAce, CONTAINER_INHERIT_ACE,
    DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetSecurityDescriptorControl, InitializeAcl,
    OBJECT_INHERIT_ACE, PROTECTED_DACL_SECURITY_INFORMATION, PSID, SE_DACL_PROTECTED,
    UNPROTECTED_DACL_SECURITY_INFORMATION,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_APPEND_DATA, FILE_EXECUTE, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_READ_EA, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA,
    FILE_WRITE_EA,
};
use windows_sys::core::PWSTR;

const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const ACCESS_DENIED_ACE_TYPE: u8 = 1;

#[derive(Debug)]
pub(crate) struct AclGuard {
    originals: Vec<OriginalDacl>,
}

unsafe impl Send for AclGuard {}
unsafe impl Sync for AclGuard {}

impl AclGuard {
    pub(crate) fn apply(fs: &[FsAccess], sid: PSID) -> Result<Self> {
        let mut guard = Self {
            originals: Vec::new(),
        };

        for entry in compile_entries(fs).map_err(|err| Error::confinement("acl", err))? {
            match entry.effect {
                RuleEffect::Allow => guard
                    .apply_allow(&entry.path, sid, rights_for(entry.right))
                    .map_err(|err| Error::confinement("acl", err))?,
                RuleEffect::Deny => guard
                    .apply_deny(&entry.path, sid, deny_mask_for(entry.right))
                    .map_err(|err| Error::confinement("acl", err))?,
            }
        }

        Ok(guard)
    }

    fn apply_allow(&mut self, path: &Path, sid: PSID, rights: u32) -> io::Result<()> {
        let original = OriginalDacl::capture(path)?;
        let explicit = explicit_access(sid, rights);
        let mut new_acl = ptr::null_mut();
        let status =
            unsafe { SetEntriesInAclW(1, &explicit, original.dacl.cast_const(), &mut new_acl) };
        win32_status(status)?;

        let set_status = unsafe {
            SetNamedSecurityInfoW(
                original.path_wide.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                new_acl,
                ptr::null_mut(),
            )
        };
        let set_result = win32_status(set_status);
        unsafe {
            LocalFree(new_acl.cast::<core::ffi::c_void>() as HLOCAL);
        }
        set_result?;

        self.originals.push(original);
        Ok(())
    }

    fn apply_deny(&mut self, path: &Path, sid: PSID, deny_mask: u32) -> io::Result<()> {
        self.apply_deny_path(path, sid, deny_mask)?;
        if std::fs::metadata(path)?.is_dir() {
            for entry in std::fs::read_dir(path)? {
                let child = entry?.path();
                self.apply_deny(&child, sid, deny_mask)?;
            }
        }
        Ok(())
    }

    fn apply_deny_path(&mut self, path: &Path, sid: PSID, deny_mask: u32) -> io::Result<()> {
        let original = OriginalDacl::capture(path)?;
        let stripped_acl = acl_without_sid_mask(original.dacl, sid, deny_mask)?;
        let set_status = unsafe {
            SetNamedSecurityInfoW(
                original.path_wide.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                stripped_acl.as_ptr().cast::<ACL>(),
                ptr::null_mut(),
            )
        };
        win32_status(set_status)?;

        self.originals.push(original);
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FsRight {
    Read,
    Write,
    Execute,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleEffect {
    Allow,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NormalizedRule {
    path: PathBuf,
    right: FsRight,
    effect: RuleEffect,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AclEntry {
    path: PathBuf,
    right: FsRight,
    effect: RuleEffect,
}

fn compile_entries(fs: &[FsAccess]) -> io::Result<Vec<AclEntry>> {
    let rules = normalize_rules(fs)?;
    Ok(compile_normalized_entries(&rules))
}

fn normalize_rules(fs: &[FsAccess]) -> io::Result<Vec<NormalizedRule>> {
    fs.iter()
        .map(|rule| {
            let (path, right, effect) = split_rule(rule);
            Ok(NormalizedRule {
                path: normalize_path(path)?,
                right,
                effect,
            })
        })
        .collect()
}

fn normalize_path(path: &Path) -> io::Result<PathBuf> {
    std::fs::canonicalize(path)
}

fn compile_normalized_entries(rules: &[NormalizedRule]) -> Vec<AclEntry> {
    let mut entries = Vec::new();
    for rule in rules {
        if final_effect(rules, rule.right, &rule.path) == rule.effect
            && !entries.iter().any(|entry: &AclEntry| {
                entry.path == rule.path && entry.right == rule.right && entry.effect == rule.effect
            })
        {
            entries.push(AclEntry {
                path: rule.path.clone(),
                right: rule.right,
                effect: rule.effect,
            });
        }
    }
    entries
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

fn rights_for(right: FsRight) -> u32 {
    match right {
        FsRight::Read => read_rights(),
        FsRight::Write => write_rights(),
        FsRight::Execute => execute_rights(),
    }
}

fn deny_mask_for(right: FsRight) -> u32 {
    match right {
        FsRight::Read => FILE_READ_DATA | FILE_READ_EA | FILE_READ_ATTRIBUTES,
        FsRight::Write => {
            FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES
        }
        FsRight::Execute => FILE_EXECUTE,
    }
}

fn acl_without_sid_mask(dacl: *mut ACL, sid: PSID, deny_mask: u32) -> io::Result<Vec<u8>> {
    if dacl.is_null() {
        return Err(io::Error::other(
            "cannot selectively deny AppContainer access on a null DACL",
        ));
    }

    let dacl_ref = unsafe { &*dacl };
    let mut storage = vec![0u8; dacl_ref.AclSize as usize];
    let initialized = unsafe {
        InitializeAcl(
            storage.as_mut_ptr().cast::<ACL>(),
            storage.len() as u32,
            ACL_REVISION,
        )
    };
    win32_bool(initialized)?;

    for index in 0..dacl_ref.AceCount as u32 {
        let mut ace = ptr::null_mut();
        let got_ace = unsafe { GetAce(dacl, index, &mut ace) };
        win32_bool(got_ace)?;

        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        let mut bytes =
            unsafe { slice::from_raw_parts(ace.cast::<u8>(), header.AceSize as usize) }.to_vec();

        if standard_ace_matches_sid(ace, sid) {
            let mask = read_standard_ace_mask(&bytes);
            let remaining = mask & !deny_mask;
            if remaining == 0 {
                continue;
            }
            write_standard_ace_mask(&mut bytes, remaining);
        }

        let added = unsafe {
            AddAce(
                storage.as_mut_ptr().cast::<ACL>(),
                ACL_REVISION,
                u32::MAX,
                bytes.as_ptr().cast(),
                bytes.len() as u32,
            )
        };
        win32_bool(added)?;
    }

    Ok(storage)
}

fn standard_ace_matches_sid(ace: *mut core::ffi::c_void, sid: PSID) -> bool {
    let header = unsafe { &*ace.cast::<ACE_HEADER>() };
    if header.AceType != ACCESS_ALLOWED_ACE_TYPE && header.AceType != ACCESS_DENIED_ACE_TYPE {
        return false;
    }

    let ace = ace.cast::<ACCESS_ALLOWED_ACE>();
    let ace_sid = unsafe {
        ptr::addr_of!((*ace).SidStart)
            .cast_mut()
            .cast::<core::ffi::c_void>()
    };
    unsafe { EqualSid(ace_sid, sid) != 0 }
}

fn read_standard_ace_mask(bytes: &[u8]) -> u32 {
    unsafe {
        ptr::read_unaligned(
            bytes
                .as_ptr()
                .add(mem::size_of::<ACE_HEADER>())
                .cast::<u32>(),
        )
    }
}

fn write_standard_ace_mask(bytes: &mut [u8], mask: u32) {
    unsafe {
        ptr::write_unaligned(
            bytes
                .as_mut_ptr()
                .add(mem::size_of::<ACE_HEADER>())
                .cast::<u32>(),
            mask,
        );
    }
}

impl Drop for AclGuard {
    fn drop(&mut self) {
        for original in self.originals.iter().rev() {
            if let Err(err) = original.restore() {
                eprintln!(
                    "guardrail warning: failed to restore ACL for {}: {err}",
                    original.path.display()
                );
            }
        }
    }
}

#[derive(Debug)]
struct OriginalDacl {
    path: PathBuf,
    path_wide: Vec<u16>,
    dacl: *mut windows_sys::Win32::Security::ACL,
    dacl_protected: bool,
    security_descriptor: windows_sys::Win32::Security::PSECURITY_DESCRIPTOR,
}

impl OriginalDacl {
    fn capture(path: &Path) -> io::Result<Self> {
        let path_wide = wide_null(path.as_os_str());
        let mut dacl = ptr::null_mut();
        let mut security_descriptor = ptr::null_mut();
        let status = unsafe {
            windows_sys::Win32::Security::Authorization::GetNamedSecurityInfoW(
                path_wide.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut dacl,
                ptr::null_mut(),
                &mut security_descriptor,
            )
        };
        win32_status(status)?;

        let mut control = 0u16;
        let mut revision = 0u32;
        let got_control = unsafe {
            GetSecurityDescriptorControl(security_descriptor, &mut control, &mut revision)
        };
        win32_bool(got_control)?;

        Ok(Self {
            path: path.to_owned(),
            path_wide,
            dacl,
            dacl_protected: control & SE_DACL_PROTECTED != 0,
            security_descriptor,
        })
    }

    fn restore(&self) -> io::Result<()> {
        let protection = if self.dacl_protected {
            PROTECTED_DACL_SECURITY_INFORMATION
        } else {
            UNPROTECTED_DACL_SECURITY_INFORMATION
        };
        let status = unsafe {
            SetNamedSecurityInfoW(
                self.path_wide.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | protection,
                ptr::null_mut(),
                ptr::null_mut(),
                self.dacl,
                ptr::null_mut(),
            )
        };
        win32_status(status)
    }
}

impl Drop for OriginalDacl {
    fn drop(&mut self) {
        if !self.security_descriptor.is_null() {
            unsafe {
                LocalFree(self.security_descriptor.cast::<core::ffi::c_void>() as HLOCAL);
            }
        }
    }
}

fn explicit_access(sid: PSID, rights: u32) -> EXPLICIT_ACCESS_W {
    EXPLICIT_ACCESS_W {
        grfAccessPermissions: rights,
        grfAccessMode: GRANT_ACCESS,
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

fn read_rights() -> u32 {
    FILE_GENERIC_READ
}

fn write_rights() -> u32 {
    FILE_GENERIC_WRITE
}

fn execute_rights() -> u32 {
    FILE_GENERIC_EXECUTE
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
    use std::process::Command;

    use guardrail_core::{Backend, SandboxConfig};
    use windows_sys::Win32::Security::Authorization::DENY_ACCESS;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_APPEND_DATA, FILE_EXECUTE, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_READ_EA,
        FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA, READ_CONTROL, SYNCHRONIZE,
    };

    use crate::{WindowsBackend, cache};

    #[test]
    fn read_access_grants_file_read_without_write_or_execute() {
        let rights = read_rights();
        assert_eq!(rights, FILE_GENERIC_READ);
        assert_eq!(
            file_specific_rights(rights),
            FILE_READ_DATA | FILE_READ_EA | FILE_READ_ATTRIBUTES
        );
        assert_eq!(
            rights & (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES),
            0
        );
        assert_eq!(rights & FILE_EXECUTE, 0);
        assert_ne!(rights, write_rights());
    }

    #[test]
    fn write_access_grants_file_write_without_read_or_execute() {
        let rights = write_rights();
        assert_eq!(rights, FILE_GENERIC_WRITE);
        assert_eq!(
            file_specific_rights(rights),
            FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES
        );
        assert_eq!(
            rights & (FILE_READ_DATA | FILE_READ_EA | FILE_READ_ATTRIBUTES | FILE_EXECUTE),
            0
        );
    }

    #[test]
    fn execute_access_grants_file_execute_without_read_or_write() {
        let rights = execute_rights();
        assert_eq!(rights, FILE_GENERIC_EXECUTE);
        assert_eq!(
            file_specific_rights(rights),
            FILE_EXECUTE | FILE_READ_ATTRIBUTES
        );
        assert_eq!(rights & (FILE_READ_DATA | FILE_READ_EA), 0);
        assert_eq!(
            rights & (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES),
            0
        );
    }

    fn file_specific_rights(rights: u32) -> u32 {
        rights & !(READ_CONTROL | SYNCHRONIZE)
    }

    #[test]
    fn explicit_allow_access_targets_sid_and_inherits_to_children() {
        let sid = 1usize as PSID;
        let access = explicit_access(sid, read_rights());
        assert_eq!(access.grfAccessMode, GRANT_ACCESS);
        assert_eq!(access.Trustee.TrusteeForm, TRUSTEE_IS_SID);
        assert_eq!(
            access.grfInheritance,
            OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
        );
        assert_eq!(access.Trustee.ptstrName as usize, sid as usize);
    }

    #[test]
    fn package_sid_deny_does_not_override_package_sid_allow() {
        let dir = temp_dir("package-deny-access-check");
        let file = dir.join("input.txt");
        std::fs::write(&file, b"guardrail").unwrap();

        let mut env = std::collections::BTreeMap::new();
        for key in ["SystemRoot", "LOCALAPPDATA", "USERPROFILE", "TEMP", "TMP"] {
            if let Ok(value) = std::env::var(key) {
                env.insert(key.into(), value);
            }
        }
        let config = SandboxConfig {
            fs: vec![FsAccess::ReadAllow(file.clone())],
            env,
            windows_cache_namespace: Some(format!("deny-check-{}", std::process::id())),
            ..SandboxConfig::default()
        };

        let appcontainer = cache::get(&config).expect("create AppContainer");
        let deny_guard = install_explicit_package_deny(&file, appcontainer.sid());
        assert_canonical_package_read_deny_then_allow(&file, appcontainer.sid());
        let backend = WindowsBackend::new(config).expect("backend");
        let mut command = Command::new("cmd");
        command.args(["/C", "type"]).arg(&file);

        let mut child = backend.spawn(command).expect("spawn");
        let status = child.wait().expect("wait");

        assert!(
            status.success(),
            "a package-SID deny ACE unexpectedly overrode the package-SID allow ACE; \
             report this Windows behavior for issue #10"
        );

        drop(deny_guard);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn compile_entries_uses_final_same_path_allow() {
        let dir = temp_dir("same-path-allow");
        let canonical = std::fs::canonicalize(&dir).unwrap();

        let entries = compile_entries(&[
            FsAccess::ReadAllow(dir.clone()),
            FsAccess::ReadDeny(dir.clone()),
            FsAccess::ReadAllow(dir.clone()),
        ])
        .unwrap();

        assert_eq!(
            entries,
            vec![AclEntry {
                path: canonical,
                right: FsRight::Read,
                effect: RuleEffect::Allow,
            }]
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn compile_entries_uses_final_same_path_deny() {
        let dir = temp_dir("same-path-deny");
        let canonical = std::fs::canonicalize(&dir).unwrap();

        let entries = compile_entries(&[
            FsAccess::ReadAllow(dir.clone()),
            FsAccess::ReadDeny(dir.clone()),
        ])
        .unwrap();

        assert_eq!(
            entries,
            vec![AclEntry {
                path: canonical,
                right: FsRight::Read,
                effect: RuleEffect::Deny,
            }]
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn compile_entries_keeps_independent_grants() {
        let dir = temp_dir("independent-grants");
        let canonical = std::fs::canonicalize(&dir).unwrap();

        let entries = compile_entries(&[
            FsAccess::ReadAllow(dir.clone()),
            FsAccess::WriteAllow(dir.clone()),
        ])
        .unwrap();

        assert_eq!(
            entries,
            vec![
                AclEntry {
                    path: canonical.clone(),
                    right: FsRight::Read,
                    effect: RuleEffect::Allow,
                },
                AclEntry {
                    path: canonical,
                    right: FsRight::Write,
                    effect: RuleEffect::Allow,
                },
            ]
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn allow_parent_deny_existing_child_preserves_ordered_entries() {
        let dir = temp_dir("allow-parent-deny-child");
        let public = dir.join("public.txt");
        let secret = dir.join("secret.txt");
        std::fs::write(&public, b"public").unwrap();
        std::fs::write(&secret, b"secret").unwrap();
        let secret = std::fs::canonicalize(secret).unwrap();
        let root = std::fs::canonicalize(&dir).unwrap();

        let entries = compile_entries(&[
            FsAccess::ReadAllow(dir.clone()),
            FsAccess::ReadDeny(secret.clone()),
        ])
        .unwrap();

        assert_eq!(
            entries,
            vec![
                AclEntry {
                    path: root,
                    right: FsRight::Read,
                    effect: RuleEffect::Allow,
                },
                AclEntry {
                    path: secret,
                    right: FsRight::Read,
                    effect: RuleEffect::Deny,
                },
            ]
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn allow_parent_deny_child_allow_grandchild_preserves_ordered_entries() {
        let dir = temp_dir("allow-deny-allow-child");
        let child = dir.join("child");
        let grandchild = child.join("grandchild.txt");
        let other = child.join("other.txt");
        std::fs::create_dir(&child).unwrap();
        std::fs::write(&grandchild, b"grandchild").unwrap();
        std::fs::write(&other, b"other").unwrap();
        let root = std::fs::canonicalize(&dir).unwrap();
        let child = std::fs::canonicalize(child).unwrap();
        let grandchild = std::fs::canonicalize(grandchild).unwrap();

        let entries = compile_entries(&[
            FsAccess::ReadAllow(dir.clone()),
            FsAccess::ReadDeny(child.clone()),
            FsAccess::ReadAllow(grandchild.clone()),
        ])
        .unwrap();

        assert_eq!(
            entries,
            vec![
                AclEntry {
                    path: root,
                    right: FsRight::Read,
                    effect: RuleEffect::Allow,
                },
                AclEntry {
                    path: child,
                    right: FsRight::Read,
                    effect: RuleEffect::Deny,
                },
                AclEntry {
                    path: grandchild,
                    right: FsRight::Read,
                    effect: RuleEffect::Allow,
                },
            ]
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn deny_parent_allow_child_preserves_ordered_entries() {
        let dir = temp_dir("deny-parent-allow-child");
        let child = dir.join("child");
        let sibling = dir.join("sibling");
        std::fs::create_dir(&child).unwrap();
        std::fs::create_dir(&sibling).unwrap();
        let root = std::fs::canonicalize(&dir).unwrap();
        let child = std::fs::canonicalize(child).unwrap();

        let entries = compile_entries(&[
            FsAccess::ReadDeny(dir.clone()),
            FsAccess::ReadAllow(child.clone()),
        ])
        .unwrap();

        assert_eq!(
            entries,
            vec![
                AclEntry {
                    path: root,
                    right: FsRight::Read,
                    effect: RuleEffect::Deny,
                },
                AclEntry {
                    path: child,
                    right: FsRight::Read,
                    effect: RuleEffect::Allow,
                },
            ]
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn compile_entries_normalizes_windows_path_identity() {
        let dir = temp_dir("case-folding");
        let lower = PathBuf::from(dir.display().to_string().to_ascii_lowercase());
        let upper = PathBuf::from(dir.display().to_string().to_ascii_uppercase());
        let canonical = std::fs::canonicalize(&dir).unwrap();

        let entries = compile_entries(&[
            FsAccess::ReadAllow(lower),
            FsAccess::ReadDeny(upper),
            FsAccess::ReadAllow(dir.clone()),
        ])
        .unwrap();

        assert_eq!(
            entries,
            vec![AclEntry {
                path: canonical,
                right: FsRight::Read,
                effect: RuleEffect::Allow,
            }]
        );

        let _ = std::fs::remove_dir_all(dir);
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

    fn install_explicit_package_deny(path: &Path, sid: PSID) -> AclGuard {
        let original = OriginalDacl::capture(path).expect("capture file DACL");
        let mut explicit = explicit_access(sid, read_rights());
        explicit.grfAccessMode = DENY_ACCESS;
        explicit.grfInheritance = 0;

        let mut new_acl = ptr::null_mut();
        let status =
            unsafe { SetEntriesInAclW(1, &explicit, original.dacl.cast_const(), &mut new_acl) };
        win32_status(status).expect("add package-SID deny ACE");

        let set_status = unsafe {
            SetNamedSecurityInfoW(
                original.path_wide.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                new_acl,
                ptr::null_mut(),
            )
        };
        let set_result = win32_status(set_status);
        unsafe {
            LocalFree(new_acl.cast::<core::ffi::c_void>() as HLOCAL);
        }
        set_result.expect("install package-SID deny ACE");

        AclGuard {
            originals: vec![original],
        }
    }

    fn assert_canonical_package_read_deny_then_allow(path: &Path, sid: PSID) {
        let current = OriginalDacl::capture(path).expect("capture characterized DACL");
        let dacl = unsafe { &*current.dacl };
        let mut deny_index = None;
        let mut allow_index = None;

        for index in 0..dacl.AceCount as u32 {
            let mut ace = ptr::null_mut();
            let got_ace = unsafe { GetAce(current.dacl, index, &mut ace) };
            win32_bool(got_ace).expect("read characterized ACE");
            if !standard_ace_matches_sid(ace, sid) {
                continue;
            }

            let header = unsafe { &*ace.cast::<ACE_HEADER>() };
            let bytes = unsafe { slice::from_raw_parts(ace.cast::<u8>(), header.AceSize as usize) };
            if read_standard_ace_mask(bytes) & FILE_READ_DATA == 0 {
                continue;
            }

            match header.AceType {
                ACCESS_DENIED_ACE_TYPE => deny_index.get_or_insert(index),
                ACCESS_ALLOWED_ACE_TYPE => allow_index.get_or_insert(index),
                _ => unreachable!(),
            };
        }

        let deny_index = deny_index.expect("package-SID read deny ACE");
        let allow_index = allow_index.expect("package-SID read allow ACE");
        assert!(
            deny_index < allow_index,
            "package-SID deny ACE must precede its allow ACE"
        );
    }

    fn unique_suffix() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    }
}
