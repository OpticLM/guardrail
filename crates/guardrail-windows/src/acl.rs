//! Temporary filesystem ACL rules for the AppContainer SID.

#![cfg(windows)]

use std::ffi::OsStr;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;

use guardrail_core::{Error, FsAccess};
use windows_sys::Win32::Foundation::{ERROR_SUCCESS, HLOCAL, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ACCESS_MODE, DENY_ACCESS, EXPLICIT_ACCESS_W, GRANT_ACCESS, SE_FILE_OBJECT, SetEntriesInAclW,
    SetNamedSecurityInfoW, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, OBJECT_INHERIT_ACE, PSID,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
};
use windows_sys::core::PWSTR;

#[derive(Debug)]
pub(crate) struct AclGuard {
    originals: Vec<OriginalDacl>,
}

unsafe impl Send for AclGuard {}

impl AclGuard {
    pub(crate) fn apply(fs: &[FsAccess], sid: PSID) -> Result<Self, Error> {
        let mut guard = Self {
            originals: Vec::new(),
        };

        for entry in compile_entries(fs).map_err(|err| Error::confinement("acl", err))? {
            guard
                .apply_path(
                    &entry.path,
                    sid,
                    rights_for(entry.right),
                    access_mode(entry.effect),
                )
                .map_err(|err| Error::confinement("acl", err))?;
        }

        Ok(guard)
    }

    fn apply_path(
        &mut self,
        path: &Path,
        sid: PSID,
        rights: u32,
        mode: ACCESS_MODE,
    ) -> io::Result<()> {
        let original = OriginalDacl::capture(path)?;
        let explicit = explicit_access(sid, rights, mode);
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
struct AclEntry {
    path: PathBuf,
    right: FsRight,
    effect: RuleEffect,
}

fn compile_entries(fs: &[FsAccess]) -> io::Result<Vec<AclEntry>> {
    let rules = normalize_rules(fs)?;
    Ok(compile_normalized_entries(&rules))
}

fn normalize_rules(fs: &[FsAccess]) -> io::Result<Vec<AclEntry>> {
    fs.iter()
        .map(|rule| {
            let (path, right, effect) = split_rule(rule);
            Ok(AclEntry {
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

fn compile_normalized_entries(rules: &[AclEntry]) -> Vec<AclEntry> {
    let mut entries = Vec::new();
    for rule in rules {
        if final_effect(rules, rule.right, &rule.path) == rule.effect
            && !entries.iter().any(|entry: &AclEntry| {
                entry.path == rule.path && entry.right == rule.right && entry.effect == rule.effect
            })
        {
            entries.push(rule.clone());
        }
    }
    entries
}

fn final_effect(rules: &[AclEntry], right: FsRight, path: &Path) -> RuleEffect {
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

fn access_mode(effect: RuleEffect) -> ACCESS_MODE {
    match effect {
        RuleEffect::Allow => GRANT_ACCESS,
        RuleEffect::Deny => DENY_ACCESS,
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

        Ok(Self {
            path: path.to_owned(),
            path_wide,
            dacl,
            security_descriptor,
        })
    }

    fn restore(&self) -> io::Result<()> {
        let status = unsafe {
            SetNamedSecurityInfoW(
                self.path_wide.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
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

fn explicit_access(sid: PSID, rights: u32, mode: ACCESS_MODE) -> EXPLICIT_ACCESS_W {
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

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_APPEND_DATA, FILE_EXECUTE, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_READ_EA,
        FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA, READ_CONTROL, SYNCHRONIZE,
    };

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
        let access = explicit_access(sid, read_rights(), GRANT_ACCESS);
        assert_eq!(access.grfAccessMode, GRANT_ACCESS);
        assert_eq!(access.Trustee.TrusteeForm, TRUSTEE_IS_SID);
        assert_eq!(
            access.grfInheritance,
            OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
        );
        assert_eq!(access.Trustee.ptstrName as usize, sid as usize);
    }

    #[test]
    fn explicit_deny_access_uses_deny_mode() {
        let sid = 1usize as PSID;
        let access = explicit_access(sid, read_rights(), DENY_ACCESS);

        assert_eq!(access.grfAccessMode, DENY_ACCESS);
        assert_eq!(access.grfAccessPermissions, FILE_GENERIC_READ);
    }

    #[test]
    fn compile_entries_uses_final_same_path_effect() {
        let entries = compile_normalized_entries(&[
            AclEntry {
                path: PathBuf::from("C:\\work"),
                right: FsRight::Read,
                effect: RuleEffect::Allow,
            },
            AclEntry {
                path: PathBuf::from("C:\\work"),
                right: FsRight::Read,
                effect: RuleEffect::Deny,
            },
            AclEntry {
                path: PathBuf::from("C:\\work"),
                right: FsRight::Read,
                effect: RuleEffect::Allow,
            },
        ]);

        assert_eq!(
            entries,
            vec![AclEntry {
                path: PathBuf::from("C:\\work"),
                right: FsRight::Read,
                effect: RuleEffect::Allow,
            }]
        );
    }

    #[test]
    fn compile_entries_keeps_independent_write_deny() {
        let entries = compile_normalized_entries(&[
            AclEntry {
                path: PathBuf::from("C:\\work"),
                right: FsRight::Read,
                effect: RuleEffect::Allow,
            },
            AclEntry {
                path: PathBuf::from("C:\\work"),
                right: FsRight::Write,
                effect: RuleEffect::Deny,
            },
        ]);

        assert_eq!(
            entries,
            vec![
                AclEntry {
                    path: PathBuf::from("C:\\work"),
                    right: FsRight::Read,
                    effect: RuleEffect::Allow,
                },
                AclEntry {
                    path: PathBuf::from("C:\\work"),
                    right: FsRight::Write,
                    effect: RuleEffect::Deny,
                },
            ]
        );
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

    fn unique_suffix() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    }
}
