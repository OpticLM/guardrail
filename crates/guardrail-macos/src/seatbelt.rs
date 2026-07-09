use std::io;

use guardrail_core::{Error, Result, SandboxConfig};

use crate::profile::SeatbeltProfile;

pub(crate) fn resolve(config: &SandboxConfig) -> Result<SeatbeltProfile> {
    let profile = if config.darwin_sandbox_profiles.is_empty() {
        crate::profile::build(config)
    } else {
        let mut imports = Vec::with_capacity(config.darwin_sandbox_profiles.len());
        for path in &config.darwin_sandbox_profiles {
            let canonical_path = std::fs::canonicalize(path)
                .map_err(|err| Error::confinement("seatbelt-profile", err))?;
            let profile_source = std::fs::read_to_string(&canonical_path)
                .map_err(|err| Error::confinement("seatbelt-profile", err))?;
            validate(&profile_source)?;

            imports.push(canonical_path);
        }
        crate::profile::build_with_imports(config, &imports)
    };

    validate(&profile.source)?;
    Ok(profile)
}

pub(crate) fn apply(profile: &SeatbeltProfile) -> Result<()> {
    painless_belt::ffi::sandbox_init(&profile.source, 0)
        .map_err(|err| Error::confinement("seatbelt", io::Error::other(err.to_string())))
}

fn validate(source: &str) -> Result<()> {
    if source.contains('\0') {
        return Err(Error::confinement(
            "seatbelt-profile",
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Seatbelt profile contains an interior NUL byte",
            ),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use guardrail_core::{FsAccess, IpcPolicy, NetworkPolicy, ResourceLimits, SandboxConfig};

    use super::*;

    fn empty_config() -> SandboxConfig {
        SandboxConfig {
            fs: vec![],
            network: NetworkPolicy::Deny,
            ipc: IpcPolicy::Strict,
            limits: ResourceLimits::default(),
            env: BTreeMap::new(),
            darwin_sandbox_profiles: vec![],
            windows_cache_namespace: None,
        }
    }

    #[test]
    fn custom_profile_paths_are_imported_before_generated_policy() {
        let first = std::env::temp_dir().join(format!(
            "guardrail-seatbelt-{}-{}.sb",
            std::process::id(),
            unique_suffix()
        ));
        let second = std::env::temp_dir().join(format!(
            "guardrail-seatbelt-{}-{}.sb",
            std::process::id(),
            unique_suffix()
        ));
        std::fs::write(&first, "(version 1)\n(allow file-read*)\n").unwrap();
        std::fs::write(&second, "(version 1)\n(allow process*)\n").unwrap();

        let first = first.canonicalize().unwrap();
        let second = second.canonicalize().unwrap();

        let config = SandboxConfig {
            fs: vec![FsAccess::ReadAllow("/generated-read".into())],
            network: NetworkPolicy::Deny,
            ipc: IpcPolicy::Strict,
            limits: ResourceLimits::default(),
            env: BTreeMap::new(),
            darwin_sandbox_profiles: vec![first.clone(), second.clone()],
            windows_cache_namespace: None,
        };
        let profile = resolve(&config).unwrap();

        let first_import = crate::profile::sbpl_string(&first);
        let second_import = crate::profile::sbpl_string(&second);
        assert_eq!(
            profile.source,
            format!(
                "(version 1)\n\
                 (import \"{first_import}\")\n\
                 (import \"{second_import}\")\n\
                 (deny default)\n\
                 (debug deny)\n\
                 (allow file-read* (subpath \"/generated-read\"))\n",
            )
        );
        let _ = std::fs::remove_file(first);
        let _ = std::fs::remove_file(second);
    }

    #[test]
    fn rejects_generated_profile_with_interior_nul_byte() {
        let config = SandboxConfig {
            fs: vec![FsAccess::ReadAllow("/tmp/has\0nul".into())],
            network: NetworkPolicy::Deny,
            ipc: IpcPolicy::Strict,
            limits: ResourceLimits::default(),
            env: BTreeMap::new(),
            darwin_sandbox_profiles: vec![],
            windows_cache_namespace: None,
        };

        let err = resolve(&config).unwrap_err();

        assert!(matches!(
            err,
            Error::Confinement {
                stage: "seatbelt-profile",
                ..
            }
        ));
    }

    #[test]
    fn rejects_custom_profile_with_interior_nul_byte() {
        let path = std::env::temp_dir().join(format!(
            "guardrail-seatbelt-nul-{}-{}.sb",
            std::process::id(),
            unique_suffix()
        ));
        std::fs::write(&path, "(version 1)\n\0\n").unwrap();

        let config = SandboxConfig {
            fs: vec![],
            network: NetworkPolicy::Deny,
            ipc: IpcPolicy::Strict,
            limits: ResourceLimits::default(),
            env: BTreeMap::new(),
            darwin_sandbox_profiles: vec![path.clone()],
            windows_cache_namespace: None,
        };
        let err = resolve(&config).unwrap_err();

        assert!(matches!(
            err,
            Error::Confinement {
                stage: "seatbelt-profile",
                ..
            }
        ));
        let _ = std::fs::remove_file(path);
    }

    fn unique_suffix() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    }
}
