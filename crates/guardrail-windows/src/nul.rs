//! One-time host configuration for the null device (`\Device\Null`).
//!
//! A guardrail child is **both** a restricted-token process and an AppContainer,
//! so an access check on any object must pass three gates: the normal enabled
//! SIDs, the token's *restricting* SIDs, and the AppContainer package/capability
//! check. The null device's default DACL satisfies none of the sandbox-relevant
//! ones:
//!
//! * It grants no AppContainer package SID at all, so the AppContainer gate
//!   fails even for reads. A Less-Privileged AppContainer (LPAC), which this
//!   backend uses, is satisfied by `ALL RESTRICTED APPLICATION PACKAGES`
//!   (S-1-15-2-2); a classic AppContainer by `ALL APPLICATION PACKAGES`
//!   (S-1-15-2-1). Granting both keeps the device reachable under either.
//! * Its only write grant is to `Everyone` (S-1-1-0), which is a normal enabled
//!   group but not a restricting SID, so the restricted gate denies writes.
//!   `Authenticated Users` (S-1-5-11) *is* a restricting SID (it rides in every
//!   child token's groups) and already holds read, so adding write to it opens
//!   the restricted gate for writes without a token change.
//!
//! Writing to `NUL` discards the data, so these grants carry no real risk, but
//! changing the device DACL needs `WRITE_DAC` and therefore elevation. The
//! driver recreates the security descriptor on every boot, so this must be
//! re-applied at each startup (a boot-start service is the intended host).
//! [`null_device_write_configured`] reports whether the grant is present.

#![cfg(windows)]

use std::io;
use std::os::windows::io::AsRawHandle;
use std::ptr;

use windows_sys::Win32::Foundation::{HLOCAL, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ACCESS_MODE, ConvertStringSidToSidW, EXPLICIT_ACCESS_W, GRANT_ACCESS, GetSecurityInfo,
    SE_KERNEL_OBJECT, SetEntriesInAclW, SetSecurityInfo, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN,
    TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, CopySid, CreateWellKnownSid, DACL_SECURITY_INFORMATION,
    EqualSid, GetAce, GetLengthSid, INHERITED_ACE, PSID, WinAuthenticatedUserSid,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    OPEN_EXISTING,
};
use windows_sys::core::PWSTR;

use crate::handle::{bool_result, owned_handle_from_raw};

const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const READ_CONTROL: u32 = 0x0002_0000;
const WRITE_DAC: u32 = 0x0004_0000;

/// Least-Privileged AppContainer trustee (`ALL RESTRICTED APPLICATION PACKAGES`).
const ALL_RESTRICTED_APPLICATION_PACKAGES: &str = "S-1-15-2-2";
/// Classic AppContainer trustee (`ALL APPLICATION PACKAGES`).
const ALL_APPLICATION_PACKAGES: &str = "S-1-15-2-1";

/// AppContainer-gate mask for `NUL`: full generic read+write. Opening `NUL`
/// with `GENERIC_READ`/`GENERIC_WRITE` also requests `SYNCHRONIZE` and
/// `READ_CONTROL`, and the AppContainer gate accumulates access only from ACEs
/// matching the package SID, so the app-package grant must carry those bits
/// too — the generic masks include them.
const APP_PACKAGE_MASK: u32 = FILE_GENERIC_READ | FILE_GENERIC_WRITE;
/// Restricted-gate mask for `NUL`: full generic write (includes `SYNCHRONIZE`
/// and `READ_CONTROL`). The device's default DACL already grants
/// `Authenticated Users` generic read, which covers the read path's restricted
/// gate.
const AUTH_USERS_MASK: u32 = FILE_GENERIC_WRITE;

/// Grant the null device the access a sandboxed child needs.
///
/// Applies, additively and idempotently (`SetEntriesInAclW` merges rights into
/// any existing ACE for the same trustee):
/// * `ALL RESTRICTED APPLICATION PACKAGES` and `ALL APPLICATION PACKAGES` —
///   read+write, to pass the AppContainer gate under LPAC or classic mode;
/// * `Authenticated Users` — write, to pass the restricted-token gate (read is
///   already granted by the device's default DACL).
///
/// Requires `WRITE_DAC` on `\Device\Null`, i.e. an elevated process; without it
/// the call fails with an access-denied error.
pub fn configure_null_device_write() -> io::Result<()> {
    let grants = required_grants()?;
    let device = open_null(READ_CONTROL | WRITE_DAC)?;

    let mut current_dacl: *mut ACL = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    // SAFETY: the handle is live; out-pointers are valid. `descriptor` owns the
    // returned security descriptor and is freed below.
    let status = unsafe {
        GetSecurityInfo(
            device.as_raw_handle(),
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut current_dacl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    let _descriptor = LocalGuard(descriptor);
    win32_status(status)?;
    if current_dacl.is_null() {
        return Err(io::Error::other(
            "the null device has a null DACL; refusing to replace it",
        ));
    }

    let explicit: Vec<EXPLICIT_ACCESS_W> = grants
        .iter()
        .map(|grant| explicit_grant(grant.sid.as_psid(), GRANT_ACCESS, grant.mask))
        .collect();
    let mut new_dacl = ptr::null_mut();
    // SAFETY: `explicit` entries reference SIDs owned by `grants`, live for the
    // call; out-pointer valid.
    let status = unsafe {
        SetEntriesInAclW(
            explicit.len() as u32,
            explicit.as_ptr(),
            current_dacl,
            &mut new_dacl,
        )
    };
    win32_status(status)?;
    let new_dacl = LocalGuard(new_dacl.cast());

    // SAFETY: the handle was opened with WRITE_DAC; `new_dacl` is a valid ACL
    // for the duration of the call. Owner/group/SACL are left untouched.
    let status = unsafe {
        SetSecurityInfo(
            device.as_raw_handle(),
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            new_dacl.0.cast(),
            ptr::null_mut(),
        )
    };
    win32_status(status)
}

/// Whether the null device already carries every grant
/// [`configure_null_device_write`] applies. Needs only `READ_CONTROL`, so it
/// runs unprivileged.
pub fn null_device_write_configured() -> io::Result<bool> {
    let grants = required_grants()?;
    let device = open_null(READ_CONTROL)?;

    let mut dacl: *mut ACL = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    // SAFETY: live handle, valid out-pointers; `descriptor` freed below.
    let status = unsafe {
        GetSecurityInfo(
            device.as_raw_handle(),
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    let _descriptor = LocalGuard(descriptor);
    win32_status(status)?;
    if dacl.is_null() {
        return Ok(false);
    }

    for grant in &grants {
        if !dacl_grants(dacl, grant.sid.as_psid(), grant.mask)? {
            return Ok(false);
        }
    }
    Ok(true)
}

struct Grant {
    sid: OwnedSid,
    mask: u32,
}

fn required_grants() -> io::Result<Vec<Grant>> {
    Ok(vec![
        Grant {
            sid: sid_from_string(ALL_RESTRICTED_APPLICATION_PACKAGES)?,
            mask: APP_PACKAGE_MASK,
        },
        Grant {
            sid: sid_from_string(ALL_APPLICATION_PACKAGES)?,
            mask: APP_PACKAGE_MASK,
        },
        Grant {
            sid: authenticated_users_sid()?,
            mask: AUTH_USERS_MASK,
        },
    ])
}

/// Whether `dacl` has an explicit (non-inherited) allow ACE for `sid` covering
/// every bit in `mask`.
fn dacl_grants(dacl: *mut ACL, sid: PSID, mask: u32) -> io::Result<bool> {
    let count = unsafe { (*dacl).AceCount };
    for index in 0..u32::from(count) {
        let mut ace = ptr::null_mut();
        // SAFETY: index within AceCount; `ace` receives a pointer into the DACL.
        bool_result(unsafe { GetAce(dacl, index, &mut ace) })?;
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        if u32::from(header.AceFlags) & INHERITED_ACE != 0
            || header.AceType != ACCESS_ALLOWED_ACE_TYPE
        {
            continue;
        }
        let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
        let ace_sid: PSID = unsafe {
            ptr::addr_of!((*ace.cast::<ACCESS_ALLOWED_ACE>()).SidStart)
                .cast_mut()
                .cast()
        };
        if unsafe { EqualSid(ace_sid, sid) } != 0 && allowed.Mask & mask == mask {
            return Ok(true);
        }
    }
    Ok(false)
}

fn open_null(access: u32) -> io::Result<std::os::windows::io::OwnedHandle> {
    let path = wide_null(r"\\.\NUL");
    // SAFETY: nul-terminated UTF-16 path; null security attributes. The device
    // exists, so OPEN_EXISTING returns its handle or INVALID_HANDLE_VALUE.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            ptr::null(),
            OPEN_EXISTING,
            0,
            ptr::null_mut(),
        )
    };
    // SAFETY: CreateFileW returns a uniquely owned handle or INVALID_HANDLE_VALUE.
    unsafe { owned_handle_from_raw(handle) }
}

struct OwnedSid(Vec<u8>);

impl OwnedSid {
    fn as_psid(&self) -> PSID {
        self.0.as_ptr().cast::<core::ffi::c_void>().cast_mut()
    }
}

fn authenticated_users_sid() -> io::Result<OwnedSid> {
    let mut len = 0u32;
    // SAFETY: the first call measures the required length into `len`.
    unsafe {
        CreateWellKnownSid(
            WinAuthenticatedUserSid,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut len,
        );
    }
    if len == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut storage = vec![0u8; len as usize];
    // SAFETY: `storage` has `len` bytes; the call fills it with the SID.
    let ok = unsafe {
        CreateWellKnownSid(
            WinAuthenticatedUserSid,
            ptr::null_mut(),
            storage.as_mut_ptr().cast(),
            &mut len,
        )
    };
    bool_result(ok)?;
    Ok(OwnedSid(storage))
}

fn sid_from_string(sid: &str) -> io::Result<OwnedSid> {
    let wide = wide_null(sid);
    let mut raw: PSID = ptr::null_mut();
    // SAFETY: nul-terminated UTF-16 string; `raw` receives a LocalAlloc'd SID.
    let ok = unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut raw) };
    bool_result(ok)?;
    let raw = LocalGuard(raw);
    // SAFETY: `raw.0` is a valid SID; copy it into owned storage before free.
    let len = unsafe { GetLengthSid(raw.0) };
    let mut storage = vec![0u8; len as usize];
    let copied = unsafe { CopySid(len, storage.as_mut_ptr().cast(), raw.0) };
    bool_result(copied)?;
    Ok(OwnedSid(storage))
}

fn explicit_grant(sid: PSID, mode: ACCESS_MODE, rights: u32) -> EXPLICIT_ACCESS_W {
    EXPLICIT_ACCESS_W {
        grfAccessPermissions: rights,
        grfAccessMode: mode,
        grfInheritance: 0,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: ptr::null_mut(),
            MultipleTrusteeOperation: 0,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_UNKNOWN,
            ptstrName: sid.cast::<u16>() as PWSTR,
        },
    }
}

struct LocalGuard(*mut core::ffi::c_void);

impl Drop for LocalGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: pointers returned by GetSecurityInfo/SetEntriesInAclW/
            // ConvertStringSidToSidW are freed with LocalFree.
            unsafe {
                LocalFree(self.0 as HLOCAL);
            }
        }
    }
}

fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn win32_status(status: u32) -> io::Result<()> {
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(status as i32))
    }
}
