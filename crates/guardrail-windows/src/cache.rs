//! Process-local cache for reusable AppContainer filesystem state.

#![cfg(windows)]

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex, OnceLock, Weak};

use guardrail_core::{Error, FsAccess, NetworkPolicy, Result, SandboxConfig};
use windows_sys::Win32::Security::SECURITY_CAPABILITIES;

use crate::acl::AclGuard;
use crate::appcontainer::{AppContainerProfile, AppContainerSecurityCapabilities};

const DEFAULT_NAMESPACE: &str = "default";
static CACHE: OnceLock<Mutex<HashMap<String, Weak<CachedAppContainer>>>> = OnceLock::new();

pub(crate) struct CachedAppContainer {
    fs: Vec<FsAccess>,
    _acl: AclGuard,
    profile: AppContainerProfile,
}

unsafe impl Send for CachedAppContainer {}
unsafe impl Sync for CachedAppContainer {}

impl CachedAppContainer {
    pub(crate) fn restricting_sid(&self) -> windows_sys::Win32::Security::PSID {
        self.profile.restricting_sid()
    }

    pub(crate) fn reallow_sid(&self) -> windows_sys::Win32::Security::PSID {
        self.profile.reallow_sid()
    }

    pub(crate) fn security_capabilities(
        &self,
        network: NetworkPolicy,
    ) -> Result<AppContainerSecurityCapabilities> {
        self.profile.security_capabilities(network)
    }
}

pub(crate) fn get(config: &SandboxConfig) -> Result<Arc<CachedAppContainer>> {
    let namespace = cache_namespace(config);
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut cache = cache.lock().unwrap_or_else(|err| err.into_inner());
    cache.retain(|_, entry| entry.strong_count() != 0);

    if let Some(entry) = cache.get(&namespace).and_then(Weak::upgrade) {
        if entry.fs == config.fs {
            return Ok(entry);
        }
        return Err(Error::confinement(
            "appcontainer-cache",
            io::Error::other(
                "windows_cache_namespace is already active with a different filesystem policy",
            ),
        ));
    }

    let entry = Arc::new(create_entry(namespace.clone(), config)?);
    cache.insert(namespace, Arc::downgrade(&entry));
    Ok(entry)
}

fn create_entry(namespace: String, config: &SandboxConfig) -> Result<CachedAppContainer> {
    let profile_name = profile_name(&namespace);
    let profile = AppContainerProfile::create(&profile_name)?;
    let acl = AclGuard::apply(
        &config.fs,
        profile.sid(),
        profile.restricting_sid(),
        profile.reallow_sid(),
    )?;
    Ok(CachedAppContainer {
        fs: config.fs.clone(),
        _acl: acl,
        profile,
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

fn profile_name(namespace: &str) -> String {
    let namespace = sanitize_namespace(namespace);
    format!("guardrail-{}-{namespace}", std::process::id())
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
        let first = profile_name("one");
        let second = profile_name("two");

        assert_ne!(first, second);
        assert!(first.ends_with("-one"));
    }

    #[test]
    fn long_or_punctuated_namespace_is_sanitized_for_profile_name() {
        let name = profile_name("team alpha/sandbox:prod with extra text");

        assert!(name.contains("-team-alpha-sandbox-"));
        assert!(name.len() <= 48);
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
    fn cache_does_not_keep_entry_alive() {
        let mut config = SandboxConfig::default();
        config.windows_cache_namespace = Some(format!(
            "cache-lifetime-{}-{}",
            std::process::id(),
            unique_suffix()
        ));

        let entry = get(&config).expect("cache entry");
        let weak = Arc::downgrade(&entry);
        drop(entry);

        assert!(weak.upgrade().is_none());
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
