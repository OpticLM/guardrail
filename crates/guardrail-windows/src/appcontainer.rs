//! AppContainer profile creation and process capability helpers.

#![cfg(windows)]

use std::ffi::OsStr;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::ptr;

use guardrail_core::{Error, NetworkPolicy, Result};
use windows_sys::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeleteAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
};
use windows_sys::Win32::Security::{
    CreateWellKnownSid, FreeSid, PSID, SECURITY_CAPABILITIES, SID_AND_ATTRIBUTES,
    WELL_KNOWN_SID_TYPE, WinCapabilityInternetClientServerSid, WinCapabilityInternetClientSid,
};

const SE_GROUP_ENABLED: u32 = 4;
const ERROR_ALREADY_EXISTS: i32 = 183;

pub(crate) struct AppContainerProfile {
    name: Vec<u16>,
    sid: Sid,
}

unsafe impl Send for AppContainerProfile {}
unsafe impl Sync for AppContainerProfile {}

impl AppContainerProfile {
    pub(crate) fn create(name: &str) -> Result<Self> {
        let name_wide = wide_null(OsStr::new(name));
        let display = wide_null(OsStr::new("guardrail sandbox"));
        let description = wide_null(OsStr::new("Reusable guardrail AppContainer profile"));
        let capabilities = CapabilitySet::for_network(NetworkPolicy::Full)
            .map_err(|err| Error::confinement("appcontainer", err))?;
        let mut created_sid = ptr::null_mut();

        let hr = unsafe {
            CreateAppContainerProfile(
                name_wide.as_ptr(),
                display.as_ptr(),
                description.as_ptr(),
                capabilities.as_ptr(),
                capabilities.len(),
                &mut created_sid,
            )
        };
        if hr < 0 && hresult_code(hr) != ERROR_ALREADY_EXISTS {
            return Err(Error::confinement("appcontainer", hresult_error(hr)));
        }
        if !created_sid.is_null() {
            unsafe {
                FreeSid(created_sid);
            }
        }

        let sid = Sid::derive_appcontainer(&name_wide)
            .map_err(|err| Error::confinement("appcontainer", err))?;

        Ok(Self {
            name: name_wide,
            sid,
        })
    }

    pub(crate) fn sid(&self) -> PSID {
        self.sid.as_psid()
    }

    pub(crate) fn security_capabilities(
        &self,
        network: NetworkPolicy,
    ) -> Result<AppContainerSecurityCapabilities> {
        AppContainerSecurityCapabilities::new(self.sid(), network)
            .map_err(|err| Error::confinement("appcontainer", err))
    }
}

impl Drop for AppContainerProfile {
    fn drop(&mut self) {
        let hr = unsafe { DeleteAppContainerProfile(self.name.as_ptr()) };
        if hr < 0 {
            eprintln!(
                "guardrail warning: failed to delete AppContainer profile {}: {}",
                String::from_utf16_lossy(&self.name[..self.name.len().saturating_sub(1)]),
                hresult_error(hr)
            );
        }
    }
}

pub(crate) struct Sid {
    storage: SidStorage,
}

enum SidStorage {
    FreeSid(PSID),
    Bytes(Vec<u8>),
}

impl Sid {
    fn derive_appcontainer(name: &[u16]) -> io::Result<Self> {
        let mut raw = ptr::null_mut();
        let hr = unsafe { DeriveAppContainerSidFromAppContainerName(name.as_ptr(), &mut raw) };
        if hr < 0 {
            return Err(hresult_error(hr));
        }
        Ok(Self {
            storage: SidStorage::FreeSid(raw),
        })
    }

    fn well_known(kind: WELL_KNOWN_SID_TYPE) -> io::Result<Self> {
        let mut len = 0u32;
        unsafe {
            CreateWellKnownSid(kind, ptr::null_mut(), ptr::null_mut(), &mut len);
        }
        if len == 0 {
            return Err(io::Error::last_os_error());
        }

        let mut storage = vec![0u8; len as usize];
        let ok = unsafe {
            CreateWellKnownSid(kind, ptr::null_mut(), storage.as_mut_ptr().cast(), &mut len)
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(Self {
            storage: SidStorage::Bytes(storage),
        })
    }

    pub(crate) fn as_psid(&self) -> PSID {
        match &self.storage {
            SidStorage::FreeSid(raw) => *raw,
            SidStorage::Bytes(storage) => storage.as_ptr().cast::<core::ffi::c_void>() as PSID,
        }
    }
}

impl Drop for Sid {
    fn drop(&mut self) {
        if let SidStorage::FreeSid(raw) = &self.storage
            && !raw.is_null()
        {
            unsafe {
                FreeSid(*raw);
            }
        }
    }
}

pub(crate) struct CapabilitySet {
    sids: Vec<Sid>,
    attributes: Vec<SID_AND_ATTRIBUTES>,
}

impl CapabilitySet {
    pub(crate) fn for_network(network: NetworkPolicy) -> io::Result<Self> {
        let mut set = Self {
            sids: Vec::new(),
            attributes: Vec::new(),
        };

        match network {
            NetworkPolicy::Deny => {}
            NetworkPolicy::OutboundOnly => {
                set.push(WinCapabilityInternetClientSid)?;
            }
            NetworkPolicy::Full => {
                set.push(WinCapabilityInternetClientSid)?;
                set.push(WinCapabilityInternetClientServerSid)?;
            }
        }

        Ok(set)
    }

    fn push(&mut self, kind: WELL_KNOWN_SID_TYPE) -> io::Result<()> {
        self.sids.push(Sid::well_known(kind)?);
        let sid = self.sids.last().expect("just pushed").as_psid();
        self.attributes.push(SID_AND_ATTRIBUTES {
            Sid: sid,
            Attributes: SE_GROUP_ENABLED,
        });
        Ok(())
    }

    fn as_ptr(&self) -> *const SID_AND_ATTRIBUTES {
        if self.attributes.is_empty() {
            ptr::null()
        } else {
            self.attributes.as_ptr()
        }
    }

    fn as_mut_ptr(&mut self) -> *mut SID_AND_ATTRIBUTES {
        if self.attributes.is_empty() {
            ptr::null_mut()
        } else {
            self.attributes.as_mut_ptr()
        }
    }

    fn len(&self) -> u32 {
        self.attributes.len() as u32
    }
}

pub(crate) struct AppContainerSecurityCapabilities {
    _capabilities: CapabilitySet,
    raw: SECURITY_CAPABILITIES,
}

impl AppContainerSecurityCapabilities {
    fn new(sid: PSID, network: NetworkPolicy) -> io::Result<Self> {
        let mut capabilities = CapabilitySet::for_network(network)?;
        let raw = SECURITY_CAPABILITIES {
            AppContainerSid: sid,
            Capabilities: capabilities.as_mut_ptr(),
            CapabilityCount: capabilities.len(),
            Reserved: 0,
        };
        Ok(Self {
            _capabilities: capabilities,
            raw,
        })
    }

    pub(crate) fn as_mut_ptr(&mut self) -> *mut SECURITY_CAPABILITIES {
        &mut self.raw
    }
}

fn wide_null(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

fn hresult_error(hr: i32) -> io::Error {
    io::Error::from_raw_os_error(hresult_code(hr))
}

fn hresult_code(hr: i32) -> i32 {
    hr & 0xffff
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_network_has_no_capabilities() {
        let set = CapabilitySet::for_network(NetworkPolicy::Deny).expect("capabilities");
        assert_eq!(set.len(), 0);
        assert!(set.as_ptr().is_null());
    }

    #[test]
    fn outbound_network_has_client_capability() {
        let set = CapabilitySet::for_network(NetworkPolicy::OutboundOnly).expect("capabilities");
        assert_eq!(set.len(), 1);
        assert_eq!(set.attributes[0].Attributes, SE_GROUP_ENABLED);
        assert!(!set.attributes[0].Sid.is_null());
    }

    #[test]
    fn full_network_is_distinct_from_outbound() {
        let set = CapabilitySet::for_network(NetworkPolicy::Full).expect("capabilities");
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn sid_length_for_capability_is_nonzero() {
        use windows_sys::Win32::Security::GetLengthSid;

        let sid = Sid::well_known(WinCapabilityInternetClientSid).expect("sid");
        assert!(unsafe { GetLengthSid(sid.as_psid()) } > 0);
    }
}
