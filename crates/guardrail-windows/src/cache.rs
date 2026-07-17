//! Process-local cache for reusable AppContainer filesystem state.

#![cfg(windows)]

use std::collections::HashMap;
use std::ffi::OsStr;
use std::io;
use std::mem;
use std::os::windows::ffi::OsStrExt;
use std::sync::{Arc, Mutex, OnceLock};

use guardrail_core::{Error, FsAccess, NetworkPolicy, Result, SandboxConfig};
use windows_sys::Win32::Security::SECURITY_CAPABILITIES;

use crate::acl::AclGuard;
use crate::appcontainer::{AppContainerProfile, AppContainerSecurityCapabilities};

const DEFAULT_NAMESPACE: &str = "default";
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

static CACHE: OnceLock<Mutex<HashMap<String, Arc<CachedAppContainer>>>> = OnceLock::new();

#[derive(Clone, Debug, PartialEq, Eq)]
struct FsPolicyKey {
    hash: u64,
    serialized: Vec<u8>,
}

pub(crate) struct CachedAppContainer {
    fs_key: FsPolicyKey,
    profile: AppContainerProfile,
    _acl: AclGuard,
}

unsafe impl Send for CachedAppContainer {}
unsafe impl Sync for CachedAppContainer {}

impl CachedAppContainer {
    pub(crate) fn security_capabilities(
        &self,
        network: NetworkPolicy,
    ) -> Result<AppContainerSecurityCapabilities> {
        self.profile.security_capabilities(network)
    }

    #[cfg(test)]
    pub(crate) fn sid(&self) -> windows_sys::Win32::Security::PSID {
        self.profile.sid()
    }
}

pub(crate) fn get(config: &SandboxConfig) -> Result<Arc<CachedAppContainer>> {
    let namespace = cache_namespace(config);
    let fs_key = filesystem_policy_key(&config.fs);
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut cache = cache.lock().unwrap_or_else(|err| err.into_inner());

    if let Some(entry) = cache.get(&namespace)
        && entry.fs_key == fs_key
    {
        return Ok(Arc::clone(entry));
    }
    if let Some(entry) = cache.get(&namespace)
        && Arc::strong_count(entry) > 1
    {
        return Err(Error::confinement(
            "appcontainer-cache",
            io::Error::other(
                "windows_cache_namespace is already active with a different filesystem policy",
            ),
        ));
    }

    // Release the cache's old entry before applying the replacement so, in the
    // ordinary single-owner case, its ACL guard restores the filesystem snapshot
    // before the new guard captures it.
    cache.remove(&namespace);
    let entry = Arc::new(create_entry(namespace.clone(), fs_key, config)?);
    cache.insert(namespace, Arc::clone(&entry));
    Ok(entry)
}

fn create_entry(
    namespace: String,
    fs_key: FsPolicyKey,
    config: &SandboxConfig,
) -> Result<CachedAppContainer> {
    let profile_name = profile_name(&namespace, fs_key.hash);
    let profile = AppContainerProfile::create(&profile_name)?;
    let acl = AclGuard::apply(&config.fs, profile.sid())?;
    Ok(CachedAppContainer {
        fs_key,
        profile,
        _acl: acl,
    })
}

fn cache_namespace(config: &SandboxConfig) -> String {
    config
        .windows_cache_namespace
        .as_deref()
        .filter(|namespace| !namespace.is_empty())
        .unwrap_or(DEFAULT_NAMESPACE)
        .to_owned()
}

fn profile_name(namespace: &str, fs_hash: u64) -> String {
    let namespace = sanitize_namespace(namespace);
    format!(
        "guardrail-{}-{namespace}-{fs_hash:016x}",
        std::process::id()
    )
}

fn sanitize_namespace(namespace: &str) -> String {
    let mut sanitized = namespace
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.' {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>();

    if sanitized.is_empty() {
        sanitized.push_str(DEFAULT_NAMESPACE);
    }
    sanitized.truncate(20);
    sanitized
}

fn filesystem_policy_key(fs: &[FsAccess]) -> FsPolicyKey {
    let serialized = serialized_filesystem_policy(fs);
    FsPolicyKey {
        hash: hash_bytes(&serialized),
        serialized,
    }
}

fn serialized_filesystem_policy(fs: &[FsAccess]) -> Vec<u8> {
    let mut serialized = Vec::new();
    serialized.extend_from_slice(&(fs.len() as u64).to_le_bytes());

    for rule in fs {
        let (tag, path) = match rule {
            FsAccess::ReadAllow(path) => (1u8, path.as_os_str()),
            FsAccess::ReadDeny(path) => (2u8, path.as_os_str()),
            FsAccess::WriteAllow(path) => (3u8, path.as_os_str()),
            FsAccess::WriteDeny(path) => (4u8, path.as_os_str()),
            FsAccess::ExecuteAllow(path) => (5u8, path.as_os_str()),
            FsAccess::ExecuteDeny(path) => (6u8, path.as_os_str()),
        };
        serialized.push(tag);
        let path_start = serialized.len();
        serialized.extend_from_slice(&0u64.to_le_bytes());
        append_os_str_bytes(&mut serialized, path);
        let path_len = serialized.len() - path_start - mem::size_of::<u64>();
        serialized[path_start..path_start + mem::size_of::<u64>()]
            .copy_from_slice(&(path_len as u64).to_le_bytes());
    }

    serialized
}

fn hash_bytes(bytes: &[u8]) -> u64 {
    let mut hash = FNV_OFFSET;
    for byte in bytes {
        hash_byte(&mut hash, *byte);
    }
    hash
}

fn append_os_str_bytes(out: &mut Vec<u8>, value: &OsStr) {
    for unit in value.encode_wide() {
        out.push((unit & 0x00ff) as u8);
        out.push((unit >> 8) as u8);
    }
}

fn hash_byte(hash: &mut u64, byte: u8) {
    *hash ^= u64::from(byte);
    *hash = hash.wrapping_mul(FNV_PRIME);
}

pub(crate) fn raw_security_capabilities(
    capabilities: &mut AppContainerSecurityCapabilities,
) -> *mut SECURITY_CAPABILITIES {
    capabilities.as_mut_ptr()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_is_part_of_profile_name() {
        let first = profile_name("one", 7);
        let second = profile_name("two", 7);

        assert_ne!(first, second);
        assert!(first.contains("-one-"));
    }

    #[test]
    fn filesystem_hash_preserves_declaration_order_and_rule_kind() {
        let a = filesystem_policy_key(&[
            FsAccess::ReadAllow("C:\\work".into()),
            FsAccess::WriteAllow("C:\\work".into()),
        ])
        .hash;
        let b = filesystem_policy_key(&[
            FsAccess::WriteAllow("C:\\work".into()),
            FsAccess::ReadAllow("C:\\work".into()),
        ])
        .hash;
        let c = filesystem_policy_key(&[
            FsAccess::ReadDeny("C:\\work".into()),
            FsAccess::WriteAllow("C:\\work".into()),
        ])
        .hash;

        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn filesystem_hash_treats_textual_path_changes_as_changes() {
        let lower = filesystem_policy_key(&[FsAccess::ReadAllow("C:\\work".into())]).hash;
        let upper = filesystem_policy_key(&[FsAccess::ReadAllow("C:\\WORK".into())]).hash;

        assert_ne!(lower, upper);
    }

    #[test]
    fn filesystem_key_length_delimits_path_bytes() {
        let single = filesystem_policy_key(&[FsAccess::ReadAllow("a\u{01ff}b".into())]);
        let split = filesystem_policy_key(&[
            FsAccess::ReadAllow("a".into()),
            FsAccess::ReadAllow("b".into()),
        ]);

        assert_ne!(single.serialized, split.serialized);
        assert_ne!(single, split);
    }

    #[test]
    fn long_or_punctuated_namespace_is_sanitized_for_profile_name() {
        let name = profile_name("team alpha/sandbox:prod with extra text", 1);

        assert!(name.contains("-team-alpha-sandbox-"));
        assert!(name.len() <= 64);
    }

    #[test]
    fn matching_namespace_and_filesystem_policy_reuses_cache_entry() {
        let mut config = SandboxConfig::default();
        config.windows_cache_namespace = Some(format!(
            "cache-hit-{}-{}",
            std::process::id(),
            unique_suffix()
        ));

        let first = get(&config).expect("first cache entry");
        let second = get(&config).expect("matching cache entry");

        assert!(Arc::ptr_eq(&first, &second));
    }

    #[test]
    fn active_namespace_rejects_different_filesystem_policy() {
        let mut first = SandboxConfig::default();
        first.windows_cache_namespace = Some(format!(
            "active-reject-{}-{}",
            std::process::id(),
            unique_suffix()
        ));
        let _entry = get(&first).expect("first cache entry");

        let mut second = first.clone();
        second
            .fs
            .push(FsAccess::ReadAllow("C:\\definitely-different".into()));

        let err = match get(&second) {
            Ok(_) => panic!("active namespace must reject replacement"),
            Err(err) => err,
        };
        assert!(matches!(
            err,
            Error::Confinement {
                stage: "appcontainer-cache",
                ..
            }
        ));
    }

    fn unique_suffix() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    }
}
