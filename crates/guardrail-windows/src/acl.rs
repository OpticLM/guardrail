//! Temporary filesystem ACL grants for the AppContainer SID.

#![cfg(windows)]

use std::ffi::OsStr;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;

use guardrail_core::{Error, FsAccess};
use windows_sys::Win32::Foundation::{ERROR_SUCCESS, HLOCAL, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    EXPLICIT_ACCESS_W, GRANT_ACCESS, SE_FILE_OBJECT, SetEntriesInAclW, SetNamedSecurityInfoW,
    TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
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

        for access in fs {
            let (path, rights) = match access {
                FsAccess::Read(path) => (path, read_rights()),
                FsAccess::Write(path) => (path, write_rights()),
                FsAccess::Execute(path) => (path, execute_rights()),
            };
            guard
                .grant_path(path, sid, rights)
                .map_err(|err| Error::confinement("acl", err))?;
        }

        Ok(guard)
    }

    fn grant_path(&mut self, path: &Path, sid: PSID, rights: u32) -> io::Result<()> {
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
    FILE_GENERIC_READ | FILE_GENERIC_WRITE
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

    #[test]
    fn read_access_is_pure_read_without_execute() {
        let rights = read_rights();
        assert_eq!(rights, FILE_GENERIC_READ);
        assert_eq!(rights & FILE_GENERIC_EXECUTE, 0);
        assert_ne!(rights, write_rights());
    }

    #[test]
    fn write_access_includes_read_write_but_not_execute() {
        let rights = write_rights();
        assert_ne!(rights & FILE_GENERIC_READ, 0);
        assert_ne!(rights & FILE_GENERIC_WRITE, 0);
        assert_eq!(rights & FILE_GENERIC_EXECUTE, 0);
    }

    #[test]
    fn execute_access_is_pure_execute() {
        let rights = execute_rights();
        assert_eq!(rights, FILE_GENERIC_EXECUTE);
        assert_eq!(rights & FILE_GENERIC_READ, 0);
        assert_eq!(rights & FILE_GENERIC_WRITE, 0);
    }

    #[test]
    fn explicit_access_targets_sid_and_inherits_to_children() {
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
}
