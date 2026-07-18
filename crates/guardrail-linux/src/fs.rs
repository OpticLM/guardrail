//! Filesystem confinement via the Landlock LSM.
//!
//! Landlock denies *everything* not explicitly allowed, including loading and
//! executing the target binary and its shared libraries. The backend compiles
//! ordered allow/deny rules into positive Landlock rules without silently
//! granting a parent subtree that contains a denied descendant.

use std::collections::BTreeSet;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};

use landlock::{
    ABI, Access, AccessFs, BitFlags, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset,
    RulesetAttr, RulesetCreated, RulesetCreatedAttr, make_bitflags,
};

use guardrail_core::{Error, FsAccess, Result};

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct CompiledRules {
    read_paths: BTreeSet<PathBuf>,
    write_paths: BTreeSet<PathBuf>,
    execute_paths: BTreeSet<PathBuf>,
}

/// Compile ordered filesystem allow/deny rules into positive Landlock paths.
///
/// This runs in the parent before `fork()`, so policy compilation errors remain
/// structured [`Error::Confinement`] values instead of being collapsed into a
/// `pre_exec` spawn failure.
pub(crate) fn compile(rules: &[FsAccess]) -> Result<CompiledRules> {
    let normalized = normalize_rules(rules)?;
    Ok(CompiledRules {
        read_paths: expand_allow_paths(&normalized, FsRight::Read)?,
        write_paths: expand_allow_paths(&normalized, FsRight::Write)?,
        execute_paths: expand_allow_paths(&normalized, FsRight::Execute)?,
    })
}

/// A Landlock ruleset fully built in the parent: ruleset creation,
/// compatibility checks, and per-path rules already happened, so the only
/// thing that crosses `fork()` is this file descriptor.
#[derive(Debug)]
pub(crate) struct PreparedRuleset {
    fd: OwnedFd,
}

impl PreparedRuleset {
    /// Enforce the ruleset on the calling thread. Called inside `pre_exec` in
    /// the freshly forked child: a single raw `landlock_restrict_self(2)` over
    /// the parent-built descriptor, so the child never runs library code that
    /// may allocate or take a lock. Requires `NO_NEW_PRIVS` (set earlier in
    /// `pre_exec`).
    ///
    /// A zero return from the kernel guarantees the ruleset is active, so the
    /// silent `NotEnforced` downgrade the landlock crate can report cannot
    /// happen through this path: the syscall either enforces or errors, and an
    /// error aborts the spawn.
    pub(crate) fn restrict_self(&self) -> std::io::Result<()> {
        // SAFETY: scalar args only; the fd is owned by self and stays open for
        // the duration of the call.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_landlock_restrict_self,
                self.fd.as_raw_fd(),
                0 as libc::c_uint,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

/// Build a Landlock ruleset for compiled positive paths, entirely in the
/// parent before `fork()`. Enforcement in the child is a separate, raw step
/// ([`PreparedRuleset::restrict_self`]); building here keeps allocation, path
/// opening, and error formatting out of the `pre_exec` closure, which the
/// [`pre_exec` contract] requires under multithreaded parents such as Node.
///
/// Fails closed: on a kernel that cannot enforce Landlock, `handle_access`
/// errors under [`CompatLevel::HardRequirement`] and the spawn is aborted
/// rather than running the child unconfined. `LinuxBackend::new` already
/// refuses to construct a backend on such kernels, so the checks here are
/// defense in depth.
///
/// [`pre_exec` contract]: std::os::unix::process::CommandExt::pre_exec
pub(crate) fn prepare(rules: &CompiledRules) -> Result<PreparedRuleset> {
    // Pin ABI v1 for the broadest kernel support; the read/exec/write rights
    // this sandbox needs all exist in v1.
    let abi = ABI::V1;

    let mut ruleset = Ruleset::default()
        // Error out instead of the default silent best-effort downgrade when
        // the kernel cannot handle the requested access rights.
        .set_compatibility(CompatLevel::HardRequirement)
        // We mediate ALL filesystem access rights: anything not granted below
        // is denied.
        .handle_access(AccessFs::from_all(abi))
        .map_err(|e| Error::confinement("landlock", e))?
        .create()
        .map_err(|e| Error::confinement("landlock", e))?
        // Per-path rules go back to best-effort: for a non-directory path the
        // crate downgrades the rule to the file-legitimate subset (e.g. drops
        // ReadDir from a file grant). That grants strictly fewer rights, never
        // more, so it cannot fail open — while HardRequirement would reject
        // every rule targeting an individual file.
        .set_compatibility(CompatLevel::BestEffort);

    ruleset = add_path_rules(
        ruleset,
        &rules.read_paths,
        access_for_right(FsRight::Read, abi),
    )?;
    ruleset = add_path_rules(
        ruleset,
        &rules.write_paths,
        access_for_right(FsRight::Write, abi),
    )?;
    ruleset = add_path_rules(
        ruleset,
        &rules.execute_paths,
        access_for_right(FsRight::Execute, abi),
    )?;

    // With every V1 right hard-required above, a created ruleset always
    // carries a real descriptor; `None` means the crate downgraded to a dummy
    // ruleset that would enforce nothing — refuse to run the child.
    let fd = Option::<OwnedFd>::from(ruleset).ok_or_else(|| {
        Error::Unsupported(
            "Landlock ruleset is not enforced on this kernel; refusing to run \
             the child without filesystem confinement"
                .into(),
        )
    })?;
    Ok(PreparedRuleset { fd })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FsRight {
    Read,
    Write,
    Execute,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleEffect {
    Allow,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NormalizedRule {
    right: FsRight,
    effect: RuleEffect,
    path: PathBuf,
}

fn normalize_rules(rules: &[FsAccess]) -> Result<Vec<NormalizedRule>> {
    rules
        .iter()
        .map(|rule| {
            let (right, effect, path) = match rule {
                FsAccess::ReadAllow(path) => (FsRight::Read, RuleEffect::Allow, path),
                FsAccess::ReadDeny(path) => (FsRight::Read, RuleEffect::Deny, path),
                FsAccess::WriteAllow(path) => (FsRight::Write, RuleEffect::Allow, path),
                FsAccess::WriteDeny(path) => (FsRight::Write, RuleEffect::Deny, path),
                FsAccess::ExecuteAllow(path) => (FsRight::Execute, RuleEffect::Allow, path),
                FsAccess::ExecuteDeny(path) => (FsRight::Execute, RuleEffect::Deny, path),
            };
            let path =
                std::fs::canonicalize(path).map_err(|err| Error::confinement("landlock", err))?;
            Ok(NormalizedRule {
                right,
                effect,
                path,
            })
        })
        .collect()
}

fn final_effect(rules: &[NormalizedRule], right: FsRight, path: &Path) -> RuleEffect {
    let mut effect = RuleEffect::Deny;
    for rule in rules {
        if rule.right == right && path.starts_with(&rule.path) {
            effect = rule.effect;
        }
    }
    effect
}

fn expand_allow_paths(rules: &[NormalizedRule], right: FsRight) -> Result<BTreeSet<PathBuf>> {
    let roots = rules
        .iter()
        .filter(|rule| rule.right == right && rule.effect == RuleEffect::Allow)
        .map(|rule| rule.path.clone())
        .collect::<BTreeSet<_>>();

    let mut allowed = BTreeSet::new();
    for root in roots {
        expand_path(rules, right, &root, &mut allowed)?;
    }
    Ok(allowed)
}

fn expand_path(
    rules: &[NormalizedRule],
    right: FsRight,
    path: &Path,
    allowed: &mut BTreeSet<PathBuf>,
) -> Result<()> {
    let metadata = std::fs::metadata(path).map_err(|err| Error::confinement("landlock", err))?;
    let effect = final_effect(rules, right, path);
    let has_boundary_below = has_descendant_boundary(rules, right, path);

    if metadata.is_dir() {
        if effect == RuleEffect::Allow && !has_boundary_below {
            allowed.insert(path.to_path_buf());
            return Ok(());
        }

        if has_boundary_below {
            for entry in
                std::fs::read_dir(path).map_err(|err| Error::confinement("landlock", err))?
            {
                let entry = entry.map_err(|err| Error::confinement("landlock", err))?;
                let child = std::fs::canonicalize(entry.path())
                    .map_err(|err| Error::confinement("landlock", err))?;
                expand_path(rules, right, &child, allowed)?;
            }
        }
    } else if effect == RuleEffect::Allow {
        allowed.insert(path.to_path_buf());
    }

    Ok(())
}

fn has_descendant_boundary(rules: &[NormalizedRule], right: FsRight, path: &Path) -> bool {
    rules
        .iter()
        .any(|rule| rule.right == right && rule.path != path && rule.path.starts_with(path))
}

fn add_path_rules(
    mut ruleset: RulesetCreated,
    paths: &BTreeSet<PathBuf>,
    access: BitFlags<AccessFs>,
) -> Result<RulesetCreated> {
    for path in paths {
        let fd = PathFd::new(path).map_err(|err| Error::confinement("landlock", err))?;
        ruleset = ruleset
            .add_rule(PathBeneath::new(fd, access))
            .map_err(|err| Error::confinement("landlock", err))?;
    }
    Ok(ruleset)
}

fn access_for_right(right: FsRight, abi: ABI) -> BitFlags<AccessFs> {
    match right {
        FsRight::Read => read_access(),
        FsRight::Write => AccessFs::from_write(abi),
        FsRight::Execute => execute_access(),
    }
}

fn read_access() -> BitFlags<AccessFs> {
    make_bitflags!(AccessFs::{ReadFile | ReadDir})
}

fn execute_access() -> BitFlags<AccessFs> {
    make_bitflags!(AccessFs::{Execute})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_parent_deny_existing_child_expands_to_allowed_siblings() {
        let temp = tempfile::tempdir().unwrap();
        let public = temp.path().join("public.txt");
        let secret = temp.path().join("secret.txt");
        std::fs::write(&public, b"public").unwrap();
        std::fs::write(&secret, b"secret").unwrap();

        let rules = normalize_rules(&[
            FsAccess::ReadAllow(temp.path().into()),
            FsAccess::ReadDeny(secret.clone()),
        ])
        .unwrap();
        let expanded = expand_allow_paths(&rules, FsRight::Read).unwrap();

        assert!(expanded.contains(&std::fs::canonicalize(public).unwrap()));
        assert!(!expanded.contains(&std::fs::canonicalize(secret).unwrap()));
        assert!(!expanded.contains(&std::fs::canonicalize(temp.path()).unwrap()));
    }

    #[test]
    fn allow_parent_deny_child_allow_grandchild_reopens_grandchild_only() {
        let temp = tempfile::tempdir().unwrap();
        let child = temp.path().join("child");
        let grandchild = child.join("grandchild.txt");
        let other = child.join("other.txt");
        std::fs::create_dir(&child).unwrap();
        std::fs::write(&grandchild, b"grandchild").unwrap();
        std::fs::write(&other, b"other").unwrap();

        let rules = normalize_rules(&[
            FsAccess::ReadAllow(temp.path().into()),
            FsAccess::ReadDeny(child.clone()),
            FsAccess::ReadAllow(grandchild.clone()),
        ])
        .unwrap();
        let expanded = expand_allow_paths(&rules, FsRight::Read).unwrap();

        assert!(expanded.contains(&std::fs::canonicalize(grandchild).unwrap()));
        assert!(!expanded.contains(&std::fs::canonicalize(child).unwrap()));
        assert!(!expanded.contains(&std::fs::canonicalize(other).unwrap()));
    }

    #[test]
    fn deny_parent_allow_child_expands_to_child_only() {
        let temp = tempfile::tempdir().unwrap();
        let child = temp.path().join("child");
        let sibling = temp.path().join("sibling");
        std::fs::create_dir(&child).unwrap();
        std::fs::create_dir(&sibling).unwrap();

        let rules = normalize_rules(&[
            FsAccess::ReadDeny(temp.path().into()),
            FsAccess::ReadAllow(child.clone()),
        ])
        .unwrap();
        let expanded = expand_allow_paths(&rules, FsRight::Read).unwrap();

        assert!(expanded.contains(&std::fs::canonicalize(child).unwrap()));
        assert!(!expanded.contains(&std::fs::canonicalize(sibling).unwrap()));
        assert!(!expanded.contains(&std::fs::canonicalize(temp.path()).unwrap()));
    }

    #[test]
    fn allow_deny_allow_same_path_final_effect_is_allow() {
        let temp = tempfile::tempdir().unwrap();
        let rules = normalize_rules(&[
            FsAccess::ReadAllow(temp.path().into()),
            FsAccess::ReadDeny(temp.path().into()),
            FsAccess::ReadAllow(temp.path().into()),
        ])
        .unwrap();

        assert_eq!(
            final_effect(
                &rules,
                FsRight::Read,
                &std::fs::canonicalize(temp.path()).unwrap()
            ),
            RuleEffect::Allow
        );
        assert_eq!(
            expand_allow_paths(&rules, FsRight::Read).unwrap(),
            BTreeSet::from([std::fs::canonicalize(temp.path()).unwrap()])
        );
    }

    #[test]
    fn allow_deny_same_path_final_effect_is_deny() {
        let temp = tempfile::tempdir().unwrap();
        let rules = normalize_rules(&[
            FsAccess::ReadAllow(temp.path().into()),
            FsAccess::ReadDeny(temp.path().into()),
        ])
        .unwrap();

        assert_eq!(
            final_effect(
                &rules,
                FsRight::Read,
                &std::fs::canonicalize(temp.path()).unwrap()
            ),
            RuleEffect::Deny
        );
        assert!(
            expand_allow_paths(&rules, FsRight::Read)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn missing_rule_path_fails_closed_during_normalization() {
        let temp = tempfile::tempdir().unwrap();
        let missing = temp.path().join("future-secret");

        let result = normalize_rules(&[
            FsAccess::ReadAllow(temp.path().into()),
            FsAccess::ReadDeny(missing),
        ]);

        assert!(matches!(
            result,
            Err(Error::Confinement {
                stage: "landlock",
                ..
            })
        ));
    }

    #[test]
    fn write_access_uses_write_only_rights() {
        let write = access_for_right(FsRight::Write, ABI::V1);

        assert_eq!(write, AccessFs::from_write(ABI::V1));
        assert!(!write.intersects(read_access()));
        assert!(!write.intersects(execute_access()));
    }
}
