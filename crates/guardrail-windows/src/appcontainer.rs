//! AppContainer profile creation and process capability helpers.

#![cfg(windows)]

use std::ffi::OsStr;
use std::io;
use std::mem;
use std::os::windows::ffi::OsStrExt;
use std::ptr;

use guardrail_core::{Error, NetworkPolicy, Result};
use windows_sys::Win32::Foundation::{HLOCAL, LocalFree, RtlNtStatusToDosError};
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
};
use windows_sys::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeleteAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
};
use windows_sys::Win32::Security::{
    AllocateAndInitializeSid, CopySid, CreateWellKnownSid, DeriveCapabilitySidsFromName, FreeSid,
    GetLengthSid, PSID, SECURITY_CAPABILITIES, SID_AND_ATTRIBUTES, SID_IDENTIFIER_AUTHORITY,
    WELL_KNOWN_SID_TYPE, WinCapabilityInternetClientServerSid, WinCapabilityInternetClientSid,
};

const SE_GROUP_ENABLED: u32 = 4;
const ERROR_ALREADY_EXISTS: i32 = 183;

pub(crate) struct AppContainerProfile {
    name: Vec<u16>,
    sid: Sid,
    restricting_sid: Sid,
    reallow_sid: Sid,
}

unsafe impl Send for AppContainerProfile {}
unsafe impl Sync for AppContainerProfile {}

impl AppContainerProfile {
    pub(crate) fn create(name: &str) -> Result<Self> {
        // Two guardrail-owned restricted-token principals: the 4-sub-authority
        // filesystem SID carries deny ACEs, the 5-sub-authority re-allow SID
        // carries the explicit grants that shadow inherited denies.
        let restricting_sid =
            Sid::random_restricting(4).map_err(|err| Error::confinement("appcontainer", err))?;
        let reallow_sid =
            Sid::random_restricting(5).map_err(|err| Error::confinement("appcontainer", err))?;
        let nonce = random_u64().map_err(|err| Error::confinement("appcontainer", err))?;
        let name = format!("{name}-{nonce:016x}");
        let name_wide = wide_null(OsStr::new(&name));
        let display = wide_null(OsStr::new("guardrail sandbox"));
        let description = wide_null(OsStr::new("guardrail sandbox"));
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
            restricting_sid,
            reallow_sid,
        })
    }

    pub(crate) fn sid(&self) -> PSID {
        self.sid.as_psid()
    }

    pub(crate) fn restricting_sid(&self) -> PSID {
        self.restricting_sid.as_psid()
    }

    pub(crate) fn reallow_sid(&self) -> PSID {
        self.reallow_sid.as_psid()
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
    /// A random SID under the null authority. Distinct sub-authority counts
    /// keep the guardrail-owned principals distinguishable from each other.
    fn random_restricting(sub_authority_count: u8) -> io::Result<Self> {
        let mut sub_authorities = [0u32; 8];
        let filled = sub_authorities
            .get_mut(..usize::from(sub_authority_count))
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "SID sub-authority count")
            })?;
        random_bytes(filled)?;

        let authority = SID_IDENTIFIER_AUTHORITY { Value: [0; 6] };
        let mut raw = ptr::null_mut();
        let allocated = unsafe {
            AllocateAndInitializeSid(
                &authority,
                sub_authority_count,
                sub_authorities[0],
                sub_authorities[1],
                sub_authorities[2],
                sub_authorities[3],
                sub_authorities[4],
                sub_authorities[5],
                sub_authorities[6],
                sub_authorities[7],
                &mut raw,
            )
        };
        if allocated == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            storage: SidStorage::FreeSid(raw),
        })
    }

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

    fn named_capability(name: &str) -> io::Result<Self> {
        let name_wide = wide_null(OsStr::new(name));
        let mut group_sids: *mut PSID = ptr::null_mut();
        let mut group_count = 0u32;
        let mut capability_sids: *mut PSID = ptr::null_mut();
        let mut capability_count = 0u32;
        let derived = unsafe {
            DeriveCapabilitySidsFromName(
                name_wide.as_ptr(),
                &mut group_sids,
                &mut group_count,
                &mut capability_sids,
                &mut capability_count,
            )
        };
        if derived == 0 {
            let err = io::Error::last_os_error();
            free_local_sid_array(group_sids, group_count);
            free_local_sid_array(capability_sids, capability_count);
            return Err(err);
        }

        let result = if capability_count == 1 && !capability_sids.is_null() {
            let raw = unsafe { *capability_sids };
            let len = unsafe { GetLengthSid(raw) };
            if len == 0 {
                Err(io::Error::last_os_error())
            } else {
                let mut storage = vec![0u8; len as usize];
                let copied = unsafe { CopySid(len, storage.as_mut_ptr().cast(), raw) };
                if copied == 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(Self {
                        storage: SidStorage::Bytes(storage),
                    })
                }
            }
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("capability {name} produced {capability_count} SIDs"),
            ))
        };

        free_local_sid_array(group_sids, group_count);
        free_local_sid_array(capability_sids, capability_count);
        result
    }

    pub(crate) fn as_psid(&self) -> PSID {
        match &self.storage {
            SidStorage::FreeSid(raw) => *raw,
            SidStorage::Bytes(storage) => storage.as_ptr().cast::<core::ffi::c_void>() as PSID,
        }
    }
}

fn random_u64() -> io::Result<u64> {
    let mut value = 0u64;
    random_bytes(std::slice::from_mut(&mut value))?;
    Ok(value)
}

fn random_bytes<T>(values: &mut [T]) -> io::Result<()> {
    let status = unsafe {
        BCryptGenRandom(
            ptr::null_mut(),
            values.as_mut_ptr().cast(),
            mem::size_of_val(values) as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status < 0 {
        let error = unsafe { RtlNtStatusToDosError(status) };
        Err(io::Error::from_raw_os_error(error as i32))
    } else {
        Ok(())
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

fn free_local_sid_array(sids: *mut PSID, count: u32) {
    if sids.is_null() {
        return;
    }
    for index in 0..count as usize {
        let sid = unsafe { *sids.add(index) };
        if !sid.is_null() {
            unsafe {
                LocalFree(sid as HLOCAL);
            }
        }
    }
    unsafe {
        LocalFree(sids.cast::<core::ffi::c_void>() as HLOCAL);
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

        // registryRead is unconditional: without it Winsock cannot load its
        // protocol catalog (WSAStartup fails), which breaks ordinary programs
        // far beyond networking — Go binaries, libcurl users, and msys tools
        // fail at startup even for pure file work. Network-enabled policies
        // additionally need the LPAC crypto and identity capabilities so
        // schannel TLS can enumerate security packages (Chromium's network
        // sandbox grants the same pair).
        match network {
            NetworkPolicy::Deny => {
                set.push_named("registryRead")?;
            }
            NetworkPolicy::OutboundOnly => {
                set.push_named("registryRead")?;
                set.push_named("lpacCryptoServices")?;
                set.push_named("lpacIdentityServices")?;
                set.push(WinCapabilityInternetClientSid)?;
            }
            NetworkPolicy::Full => {
                set.push_named("registryRead")?;
                set.push_named("lpacCryptoServices")?;
                set.push_named("lpacIdentityServices")?;
                set.push(WinCapabilityInternetClientSid)?;
                set.push(WinCapabilityInternetClientServerSid)?;
            }
        }

        Ok(set)
    }

    fn push(&mut self, kind: WELL_KNOWN_SID_TYPE) -> io::Result<()> {
        self.push_sid(Sid::well_known(kind)?)
    }

    fn push_named(&mut self, name: &str) -> io::Result<()> {
        self.push_sid(Sid::named_capability(name)?)
    }

    fn push_sid(&mut self, sid: Sid) -> io::Result<()> {
        self.sids.push(sid);
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
    fn deny_network_keeps_only_registry_read() {
        let set = CapabilitySet::for_network(NetworkPolicy::Deny).expect("capabilities");
        assert_eq!(set.len(), 1);
        assert!(!set.as_ptr().is_null());
    }

    #[test]
    fn outbound_network_has_client_capability() {
        let set = CapabilitySet::for_network(NetworkPolicy::OutboundOnly).expect("capabilities");
        assert_eq!(set.len(), 4);
        assert_eq!(set.attributes[0].Attributes, SE_GROUP_ENABLED);
        assert!(!set.attributes[0].Sid.is_null());
    }

    #[test]
    fn full_network_is_distinct_from_outbound() {
        let set = CapabilitySet::for_network(NetworkPolicy::Full).expect("capabilities");
        assert_eq!(set.len(), 5);
    }

    #[test]
    fn sid_length_for_capability_is_nonzero() {
        use windows_sys::Win32::Security::GetLengthSid;

        let sid = Sid::well_known(WinCapabilityInternetClientSid).expect("sid");
        assert!(unsafe { GetLengthSid(sid.as_psid()) } > 0);
    }
}
