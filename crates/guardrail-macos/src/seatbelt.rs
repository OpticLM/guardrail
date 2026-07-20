use std::collections::BTreeMap;
use std::ffi::{CStr, CString, OsStr};
use std::io;
use std::os::unix::ffi::OsStrExt;

use guardrail_core::{Error, Result, SandboxCommand, SandboxConfig};

use crate::profile::SeatbeltProfile;

pub(crate) const SANDBOX_EXEC_PATH: &str = "/usr/bin/sandbox-exec";
const SANDBOX_EXEC: &CStr = c"/usr/bin/sandbox-exec";

/// A Seatbelt profile encoded in the parent for the launcher's argv.
#[derive(Clone)]
pub(crate) struct PreparedProfile(CString);

/// Parent-built argv and envp for the dedicated Seatbelt launcher.
///
/// The raw pointer tables refer into the owned `CString` buffers. Moving this
/// struct does not move those buffers, and neither table nor storage is
/// mutated after construction.
pub(crate) struct PreparedLaunch {
    _argv_storage: Vec<CString>,
    argv: Box<[*const libc::c_char]>,
    _env_storage: Vec<CString>,
    envp: Box<[*const libc::c_char]>,
}

// SAFETY: the pointer tables are immutable and point only into CString
// allocations owned by the same struct, whose addresses remain stable when
// the struct moves between threads or into the pre_exec closure.
unsafe impl Send for PreparedLaunch {}
// SAFETY: as above; shared access cannot mutate either storage or pointers.
unsafe impl Sync for PreparedLaunch {}

pub(crate) fn probe_launcher() -> io::Result<()> {
    // SAFETY: SANDBOX_EXEC is a live, nul-terminated absolute path.
    let rc = unsafe { libc::access(SANDBOX_EXEC.as_ptr(), libc::X_OK) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

impl PreparedLaunch {
    /// Build a `sandbox-exec -p PROFILE -- PROGRAM ARGS...` invocation and the
    /// exact environment declared by the sandbox configuration.
    pub(crate) fn new(
        profile: &PreparedProfile,
        command: &SandboxCommand,
        env: &BTreeMap<String, String>,
    ) -> io::Result<Self> {
        let mut argv_storage = Vec::with_capacity(command.args.len() + 5);
        argv_storage.push(SANDBOX_EXEC.to_owned());
        argv_storage.push(c"-p".to_owned());
        argv_storage.push(profile.0.clone());
        argv_storage.push(c"--".to_owned());
        argv_storage.push(os_string(&command.program)?);
        for arg in &command.args {
            argv_storage.push(os_string(arg)?);
        }
        let argv = pointer_table(&argv_storage);

        let mut env_storage = Vec::with_capacity(env.len());
        for (key, value) in env {
            let mut entry = Vec::with_capacity(key.len() + value.len() + 1);
            entry.extend_from_slice(key.as_bytes());
            entry.push(b'=');
            entry.extend_from_slice(value.as_bytes());
            env_storage.push(c_string(entry)?);
        }
        let envp = pointer_table(&env_storage);

        Ok(Self {
            _argv_storage: argv_storage,
            argv,
            _env_storage: env_storage,
            envp,
        })
    }

    /// Replace the fork child with the dedicated Seatbelt launcher.
    ///
    /// `execve` is async-signal-safe. On success this never returns; the fresh
    /// sandbox-exec image parses and applies the profile while single-threaded,
    /// then execs the requested command.
    pub(crate) fn exec(&self) -> io::Result<()> {
        // SAFETY: both pointer tables are null-terminated and every preceding
        // pointer names a live, nul-terminated CString owned by self.
        unsafe {
            libc::execve(
                SANDBOX_EXEC.as_ptr(),
                self.argv.as_ptr(),
                self.envp.as_ptr(),
            );
        }
        Err(io::Error::last_os_error())
    }
}

fn os_string(value: &OsStr) -> io::Result<CString> {
    c_string(value.as_bytes().to_vec())
}

fn c_string(bytes: Vec<u8>) -> io::Result<CString> {
    CString::new(bytes).map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))
}

fn pointer_table(strings: &[CString]) -> Box<[*const libc::c_char]> {
    strings
        .iter()
        .map(|value| value.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect()
}

pub(crate) fn resolve(config: &SandboxConfig) -> Result<SeatbeltProfile> {
    let profile = if config.darwin_sandbox_profiles.is_empty() {
        crate::profile::build(config)?
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
        crate::profile::build_with_imports(config, &imports)?
    };

    validate(&profile.source)?;
    Ok(profile)
}

pub(crate) fn prepare(profile: SeatbeltProfile) -> Result<PreparedProfile> {
    CString::new(profile.source)
        .map(PreparedProfile)
        .map_err(|err| Error::confinement("seatbelt-profile", err))
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

    use guardrail_core::{
        FsAccess, IpcPolicy, NetworkPolicy, ResourceLimits, SandboxConfig, UserNamespacePolicy,
    };

    use super::*;

    #[test]
    fn launcher_argv_and_env_are_fully_prepared() {
        let profile = PreparedProfile(CString::new("(version 1)\n(deny default)\n").unwrap());
        let mut command = SandboxCommand::new("/tmp/program");
        command.args = vec!["first".into(), "two words".into()];
        let env = BTreeMap::from([
            ("EMPTY".to_owned(), String::new()),
            ("PATH".to_owned(), "/usr/bin:/bin".to_owned()),
        ]);

        let launcher = PreparedLaunch::new(&profile, &command, &env).unwrap();

        let argv = launcher
            ._argv_storage
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            argv,
            [
                SANDBOX_EXEC_PATH,
                "-p",
                "(version 1)\n(deny default)\n",
                "--",
                "/tmp/program",
                "first",
                "two words",
            ]
        );
        let envp = launcher
            ._env_storage
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(envp, ["EMPTY=", "PATH=/usr/bin:/bin"]);

        assert_eq!(launcher.argv.len(), launcher._argv_storage.len() + 1);
        assert!(launcher.argv.last().unwrap().is_null());
        for (pointer, value) in launcher.argv.iter().zip(&launcher._argv_storage) {
            assert_eq!(*pointer, value.as_ptr());
        }
        assert_eq!(launcher.envp.len(), launcher._env_storage.len() + 1);
        assert!(launcher.envp.last().unwrap().is_null());
        for (pointer, value) in launcher.envp.iter().zip(&launcher._env_storage) {
            assert_eq!(*pointer, value.as_ptr());
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
            linux_ipc: IpcPolicy::Strict,
            linux_unix_sockets: vec![],
            limits: ResourceLimits::default(),
            env: BTreeMap::new(),
            darwin_sandbox_profiles: vec![first.clone(), second.clone()],
            linux_user_namespaces: UserNamespacePolicy::Deny,
            windows_cache_namespace: None,
        };
        let profile = resolve(&config).unwrap();

        let first_import = crate::profile::sbpl_string(&first).unwrap();
        let second_import = crate::profile::sbpl_string(&second).unwrap();
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
            linux_ipc: IpcPolicy::Strict,
            linux_unix_sockets: vec![],
            limits: ResourceLimits::default(),
            env: BTreeMap::new(),
            darwin_sandbox_profiles: vec![],
            linux_user_namespaces: UserNamespacePolicy::Deny,
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
            linux_ipc: IpcPolicy::Strict,
            linux_unix_sockets: vec![],
            limits: ResourceLimits::default(),
            env: BTreeMap::new(),
            darwin_sandbox_profiles: vec![path.clone()],
            linux_user_namespaces: UserNamespacePolicy::Deny,
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
