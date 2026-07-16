//! Kernel capability probes backing [`Backend::probe_support`].
//!
//! Landlock enforcement is verified on a disposable thread, leaving the
//! caller unrestricted. The seccomp probe is deliberately narrower:
//! `SECCOMP_GET_ACTION_AVAIL` reports whether the kernel knows the filters'
//! `Trap` and `Errno` actions, but does not prove that an ambient policy will
//! permit installing the filters.
//!
//! [`Backend::probe_support`]: guardrail_core::Backend::probe_support

use landlock::{
    ABI, Access, AccessFs, CompatLevel, Compatible, Ruleset, RulesetAttr, RulesetStatus,
};

use guardrail_core::{Error, Result};

/// Probe the required Linux features without changing the calling thread.
pub(crate) fn probe_required_features() -> Result<()> {
    probe_landlock_enforcement()?;
    probe_seccomp_action_availability()?;
    Ok(())
}

/// Verify that Landlock can enforce the same ABI v1 access rights `fs::apply`
/// uses. The probe runs on a disposable thread because Landlock confinement
/// cannot be removed once applied.
fn probe_landlock_enforcement() -> Result<()> {
    std::thread::Builder::new()
        .name("guardrail-landlock-probe".into())
        .spawn(enforce_landlock_on_probe_thread)
        .map_err(|e| Error::confinement("landlock probe", e))?
        .join()
        .map_err(|_| {
            Error::confinement(
                "landlock probe",
                std::io::Error::other("Landlock probe thread panicked"),
            )
        })?
}

fn enforce_landlock_on_probe_thread() -> Result<()> {
    let status = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(ABI::V1))
        .and_then(|ruleset| ruleset.create())
        .and_then(|ruleset| ruleset.restrict_self())
        .map_err(|e| {
            Error::Unsupported(format!(
                "Landlock (filesystem confinement) could not be enforced: {e}"
            ))
        })?;

    if status.ruleset != RulesetStatus::FullyEnforced {
        return Err(Error::Unsupported(format!(
            "Landlock (filesystem confinement) was not fully enforced: {:?}",
            status.ruleset
        )));
    }
    Ok(())
}

/// Query whether the kernel reports the seccomp actions used by the backend's
/// filters: `Trap` for violations and `Errno` for the io_uring denial. This
/// does not install a filter and is not proof that a later
/// `SECCOMP_SET_MODE_FILTER` call will be permitted or have resources.
fn probe_seccomp_action_availability() -> Result<()> {
    for (name, action) in [
        ("Trap", libc::SECCOMP_RET_TRAP),
        ("Errno", libc::SECCOMP_RET_ERRNO),
    ] {
        // SAFETY: SECCOMP_GET_ACTION_AVAIL only reads `action`; no filter is
        // installed and no process state changes.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_GET_ACTION_AVAIL,
                0,
                &action as *const libc::c_uint,
            )
        };
        if rc != 0 {
            return Err(Error::Unsupported(format!(
                "seccomp-BPF {name} action availability probe failed; filter installation was not tested: {}",
                std::io::Error::last_os_error()
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use landlock::{PathBeneath, PathFd, RulesetCreatedAttr};

    use super::*;

    #[test]
    fn landlock_probe_detects_the_ruleset_layer_limit() {
        match probe_landlock_enforcement() {
            Ok(()) => {}
            Err(Error::Unsupported(reason)) => {
                eprintln!("skipping: Landlock unavailable: {reason}");
                return;
            }
            Err(other) => panic!("Landlock probe failed unexpectedly: {other:?}"),
        }

        let result = std::thread::spawn(|| {
            for _ in 0..16 {
                if apply_permissive_landlock_layer().is_err() {
                    break;
                }
            }
            probe_landlock_enforcement()
        })
        .join()
        .expect("layer-limit test thread");

        assert!(
            matches!(result, Err(Error::Unsupported(_))),
            "the probe must reject a thread that cannot enforce another Landlock layer: {result:?}"
        );
    }

    fn apply_permissive_landlock_layer() -> std::result::Result<(), landlock::RulesetError> {
        let access = AccessFs::from_all(ABI::V1);
        let status = Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(access)?
            .create()?
            .add_rule(PathBeneath::new(
                PathFd::new("/").expect("open root"),
                access,
            ))?
            .restrict_self()?;
        assert_eq!(status.ruleset, RulesetStatus::FullyEnforced);
        Ok(())
    }
}
