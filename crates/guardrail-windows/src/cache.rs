//! Cross-process persistent cache for reusable AppContainer filesystem state.
//!
//! A namespace's AppContainer profile, principals, on-disk ACEs, and manifest
//! all persist beyond the process: profile names and restricting SIDs are
//! derived deterministically from the namespace, ACEs are not stripped when a
//! sandbox drops, and the manifest (see [`crate::manifest`]) lets the next run
//! verify, diff, or rebuild instead of always re-propagating ACEs over the
//! whole tree. [`cleanup_namespace`] retires everything explicitly.

#![cfg(windows)]

use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock, Weak};

use guardrail_core::{Error, FsAccess, NetworkPolicy, Result, SandboxConfig};
use windows_sys::Win32::Security::SECURITY_CAPABILITIES;

use crate::acl::{AclGuard, Principals};
use crate::appcontainer::{AppContainerProfile, AppContainerSecurityCapabilities};
use crate::manifest::{self, ActiveMarker};

const DEFAULT_NAMESPACE: &str = "default";
static CACHE: OnceLock<Mutex<HashMap<String, Weak<CachedAppContainer>>>> = OnceLock::new();

pub(crate) struct CachedAppContainer {
    fs: Vec<FsAccess>,
    _acl: AclGuard,
    _marker: ActiveMarker,
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

    let entry = Arc::new(create_entry(&namespace, config)?);
    cache.insert(namespace, Arc::downgrade(&entry));
    Ok(entry)
}

fn create_entry(namespace: &str, config: &SandboxConfig) -> Result<CachedAppContainer> {
    let sanitized = sanitized_namespace_id(namespace);
    let dir = manifest::namespace_dir(config, &sanitized)
        .map_err(|err| Error::confinement("appcontainer-cache", err))?;

    let entries = crate::acl::canonical_rules(&config.fs)?;
    let previous = manifest::load(&dir).map_err(|err| Error::confinement("acl-manifest", err))?;
    // Another live process may keep using the namespace only when the policy
    // is unchanged; a conflicting policy while active is an error.
    let unchanged = previous.as_deref() == Some(&entries);
    let marker = ActiveMarker::acquire(&dir, unchanged)
        .map_err(|err| Error::confinement("appcontainer-cache", err))?;

    let profile = AppContainerProfile::create(&profile_name(&sanitized), &sanitized)?;
    let principals = Principals::new(
        profile.sid(),
        profile.restricting_sid(),
        profile.reallow_sid(),
    )
    .map_err(|err| Error::confinement("acl", err))?;
    let acl = AclGuard::apply(
        &entries,
        previous.as_deref(),
        &principals,
        config.windows_acl_verification,
    )?;
    manifest::store(&dir, &entries).map_err(|err| Error::confinement("acl-manifest", err))?;

    Ok(CachedAppContainer {
        fs: config.fs.clone(),
        _acl: acl,
        _marker: marker,
        profile,
    })
}

/// Retire a namespace: remove every guardrail ACE the manifest records,
/// delete the AppContainer profile, and remove the manifest directory.
///
/// `namespace`/`manifest_dir` mirror `SandboxConfig::windows_cache_namespace`
/// and `windows_manifest_dir`. Fails when the namespace is active in any
/// process.
pub fn cleanup_namespace(
    namespace: Option<&str>,
    manifest_dir: Option<&Path>,
) -> io::Result<()> {
    let namespace = namespace
        .filter(|namespace| !namespace.is_empty())
        .unwrap_or(DEFAULT_NAMESPACE);
    let sanitized = sanitized_namespace_id(namespace);
    let mut config = SandboxConfig::default();
    config.windows_manifest_dir = manifest_dir.map(Path::to_path_buf);
    let dir = manifest::namespace_dir(&config, &sanitized)?;

    if ActiveMarker::held_elsewhere(&dir) {
        return Err(io::Error::other(
            "cannot clean up a windows_cache_namespace while it is active in a process",
        ));
    }

    let profile_name = profile_name(&sanitized);
    if let Some(rules) = manifest::load(&dir)? {
        let (package, filesystem, reallow) =
            crate::appcontainer::namespace_principals(&profile_name, &sanitized)?;
        for rule in &rules {
            for sid in [package.as_psid(), filesystem.as_psid(), reallow.as_psid()] {
                match crate::acl::remove_acl_entries(&rule.path, sid) {
                    Ok(()) => {}
                    // The root may be long gone; nothing to strip.
                    Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                    Err(err) => return Err(err),
                }
            }
        }
    }
    crate::appcontainer::delete_profile(&profile_name)?;
    match std::fs::remove_dir_all(&dir) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

fn cache_namespace(config: &SandboxConfig) -> String {
    config
        .windows_cache_namespace
        .as_deref()
        .filter(|namespace| !namespace.is_empty())
        .unwrap_or(DEFAULT_NAMESPACE)
        .to_owned()
}

/// Stable per-namespace identifier: the sanitized display form plus a hash of
/// the full namespace, so sanitization/truncation cannot make two namespaces
/// collide.
fn sanitized_namespace_id(namespace: &str) -> String {
    let hash = manifest::fnv1a64(namespace.as_bytes()) as u32;
    format!("{}-{hash:08x}", sanitize_namespace(namespace))
}

fn profile_name(sanitized_id: &str) -> String {
    format!("guardrail-{sanitized_id}")
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

    fn unique_namespace(label: &str) -> String {
        format!(
            "{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )
    }

    fn temp_manifest_config(label: &str) -> SandboxConfig {
        let mut config = SandboxConfig::default();
        config.windows_cache_namespace = Some(unique_namespace(label));
        config.windows_manifest_dir =
            Some(std::env::temp_dir().join(format!("guardrail-cache-test-{label}")));
        config
    }

    #[test]
    fn namespace_is_part_of_profile_name() {
        let first = profile_name(&sanitized_namespace_id("one"));
        let second = profile_name(&sanitized_namespace_id("two"));

        assert_ne!(first, second);
        assert!(first.starts_with("guardrail-one-"));
    }

    #[test]
    fn profile_name_is_stable_across_calls() {
        assert_eq!(
            profile_name(&sanitized_namespace_id("stable")),
            profile_name(&sanitized_namespace_id("stable")),
        );
    }

    #[test]
    fn long_or_punctuated_namespace_is_sanitized_but_distinct() {
        let long_a = sanitized_namespace_id("team alpha/sandbox:prod with extra text");
        let long_b = sanitized_namespace_id("team alpha/sandbox:prod with other text");

        assert!(long_a.contains("team-alpha-sandbox-"));
        // Truncation alone would collide; the hash keeps them apart.
        assert_ne!(long_a, long_b);
    }

    #[test]
    fn matching_namespace_and_filesystem_policy_reuses_cache_entry() {
        let config = temp_manifest_config("cache-hit");

        let first = get(&config).expect("first cache entry");
        let second = get(&config).expect("matching cache entry");

        assert!(Arc::ptr_eq(&first, &second));
        drop((first, second));
        cleanup_namespace(
            config.windows_cache_namespace.as_deref(),
            config.windows_manifest_dir.as_deref(),
        )
        .expect("cleanup");
    }

    #[test]
    fn cache_does_not_keep_entry_alive() {
        let config = temp_manifest_config("cache-lifetime");

        let entry = get(&config).expect("cache entry");
        let weak = Arc::downgrade(&entry);
        drop(entry);

        assert!(weak.upgrade().is_none());
        cleanup_namespace(
            config.windows_cache_namespace.as_deref(),
            config.windows_manifest_dir.as_deref(),
        )
        .expect("cleanup");
    }

    #[test]
    fn active_namespace_rejects_different_filesystem_policy() {
        let first = temp_manifest_config("active-reject");
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

    #[test]
    fn cleanup_refuses_active_namespace() {
        let config = temp_manifest_config("cleanup-active");
        let _entry = get(&config).expect("cache entry");

        let err = cleanup_namespace(
            config.windows_cache_namespace.as_deref(),
            config.windows_manifest_dir.as_deref(),
        )
        .expect_err("cleanup must refuse an active namespace");
        assert!(err.to_string().contains("active"));
    }
}
