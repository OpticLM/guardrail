//! Filesystem confinement via the Landlock LSM.
//!
//! Landlock denies *everything* not explicitly allowed, including loading and
//! executing the target binary and its shared libraries. The backend therefore
//! applies only the declarative [`FsAccess`] grants; callers must explicitly
//! grant any read or execute access required for the program they spawn.

use landlock::{
    ABI, Access, AccessFs, BitFlags, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus,
    make_bitflags, path_beneath_rules,
};

use guardrail_core::{Error, FsAccess};

/// Build and enforce a Landlock ruleset for `rules`. Called inside `pre_exec`.
///
/// Best-effort by design: on a kernel without Landlock, `restrict_self()`
/// returns [`RulesetStatus::NotEnforced`] rather than erroring, and we return
/// `Ok(())` after warning — hard-failing would make the library unusable on
/// older kernels. A genuine [`landlock::RulesetError`] is wrapped in
/// [`Error::confinement`].
pub(crate) fn apply(rules: &[FsAccess]) -> Result<(), Error> {
    // Pin ABI v1 for the broadest kernel support; the read/exec/write rights
    // this sandbox needs all exist in v1.
    let abi = ABI::V1;

    let mut ruleset = Ruleset::default()
        // We mediate ALL filesystem access rights: anything not granted below
        // is denied.
        .handle_access(AccessFs::from_all(abi))
        .map_err(|e| Error::confinement("landlock", e))?
        .create()
        .map_err(|e| Error::confinement("landlock", e))?;

    // Declared read grants: file reads and directory reads only.
    for rule in rules {
        if let FsAccess::Read(p) = rule {
            ruleset = ruleset
                .add_rules(path_beneath_rules([p], read_access()))
                .map_err(|e| Error::confinement("landlock", e))?;
        }
    }
    // Declared write grants retain the existing read+write API contract, but
    // intentionally do not grant execute.
    for rule in rules {
        if let FsAccess::Write(p) = rule {
            ruleset = ruleset
                .add_rules(path_beneath_rules(
                    [p],
                    read_access() | AccessFs::from_write(abi),
                ))
                .map_err(|e| Error::confinement("landlock", e))?;
        }
    }
    // Declared execute grants are independent from read and write grants.
    for rule in rules {
        if let FsAccess::Execute(p) = rule {
            ruleset = ruleset
                .add_rules(path_beneath_rules([p], execute_access()))
                .map_err(|e| Error::confinement("landlock", e))?;
        }
    }

    let status = ruleset
        .restrict_self()
        .map_err(|e| Error::confinement("landlock", e))?;

    if status.ruleset == RulesetStatus::NotEnforced {
        eprintln!(
            "guardrail: warning — Landlock not enforced on this kernel; \
             filesystem confinement is INACTIVE"
        );
    }
    Ok(())
}

fn read_access() -> BitFlags<AccessFs> {
    make_bitflags!(AccessFs::{ReadFile | ReadDir})
}

fn execute_access() -> BitFlags<AccessFs> {
    make_bitflags!(AccessFs::{Execute})
}
