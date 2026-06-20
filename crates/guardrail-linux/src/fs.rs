//! Filesystem confinement via the Landlock LSM.
//!
//! Landlock denies *everything* not explicitly allowed — including loading and
//! executing the target binary and its shared libraries. So we always grant
//! read+execute on a fixed set of system directories (see [`SYSTEM_READ_DIRS`])
//! in addition to the declarative [`FsAccess`] grants, then enforce the ruleset
//! on the calling thread inside `pre_exec`.

use landlock::{
    ABI, Access, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus,
    path_beneath_rules,
};

use guardrail_core::{Error, FsAccess};

/// Read-only system directories always granted so the target binary, its
/// dynamic loader, and shared libraries can be loaded and executed.
///
/// `/usr`, `/lib*`, `/bin`, `/sbin` cover binaries + shared objects + the
/// dynamic loader; `/etc` covers `ld.so.cache`, `nsswitch.conf`, locale, etc.
/// These are **read-only** — write is never granted by default. The set
/// intentionally excludes `/home`, `/root`, `/tmp`, `/var`, `/proc`, `/sys`,
/// and `/dev`; widening it is a security tradeoff.
const SYSTEM_READ_DIRS: &[&str] = &["/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc"];

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

    let read_paths: Vec<&str> = SYSTEM_READ_DIRS.to_vec();

    let mut ruleset = Ruleset::default()
        // We mediate ALL filesystem access rights: anything not granted below
        // is denied.
        .handle_access(AccessFs::from_all(abi))
        .map_err(|e| Error::confinement("landlock", e))?
        .create()
        .map_err(|e| Error::confinement("landlock", e))?
        // Default read-only system directories. `path_beneath_rules` silently
        // ignores paths that cannot be opened (e.g. `/lib64` on a distro that
        // lacks it), which is exactly the best-effort behavior we want here.
        .add_rules(path_beneath_rules(read_paths, AccessFs::from_read(abi)))
        .map_err(|e| Error::confinement("landlock", e))?;

    // Declared read grants (read + execute + readdir on the subtree).
    for rule in rules {
        if let FsAccess::Read(p) = rule {
            ruleset = ruleset
                .add_rules(path_beneath_rules([p], AccessFs::from_read(abi)))
                .map_err(|e| Error::confinement("landlock", e))?;
        }
    }
    // Declared write grants (full access on the subtree).
    for rule in rules {
        if let FsAccess::Write(p) = rule {
            ruleset = ruleset
                .add_rules(path_beneath_rules([p], AccessFs::from_all(abi)))
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
