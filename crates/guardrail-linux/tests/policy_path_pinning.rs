#![cfg(target_os = "linux")]

//! Regression tests for policy-path durability.
//!
//! `LinuxBackend` is reusable, and the policy it compiles outlives the process
//! that compiled it. Both confinement layers used to re-derive their targets
//! from the canonicalized path *strings* at each spawn — `fs::prepare`
//! re-opened every Landlock allow root, and the child re-resolved every
//! mount-mask target in its own namespace. A sandboxed child that may write a
//! directory on the way to a policy path could move it aside and leave a decoy
//! at the old name, so the grant or mask landed on an inode of its choosing.
//!
//! Two changes close that, and both are exercised here:
//!
//! * rule paths are canonicalized and pinned once, in `LinuxBackend::new`, so
//!   within a live backend a redirected path can never be confined by mistake
//!   — Landlock holds the descriptor, and the child checks each mask target
//!   against the identity the parent recorded;
//! * pinning is in-process, so it cannot survive the sandbox exiting. Policy
//!   shapes whose paths the sandbox could relocate are therefore refused at
//!   compile time, because a decoy staged in one run would otherwise be
//!   confined by the next.
//!
//! Every attacker step below runs *inside* the sandbox, so nothing here relies
//! on host privileges the confined process would not have.

use guardrail_core::{Backend, Error, FsAccess, SandboxConfig};
use guardrail_linux::LinuxBackend;
use tempfile::TempDir;

mod common;

/// Whether the probe ran and was allowed (exit 0).
fn run(backend: &LinuxBackend, args: &[&str]) -> bool {
    let mut child = backend.spawn(common::probe(args)).expect("spawn");
    child.wait().expect("wait").success()
}

/// Whether this host can enforce the parts under test.
fn enforced() -> bool {
    if !common::landlock_enforced() {
        eprintln!("skipping: Landlock not enforced on this kernel");
        return false;
    }
    if let Some(reason) = common::mount_masking_unsupported_reason() {
        eprintln!("skipping: mount masking unsupported: {reason}");
        return false;
    }
    true
}

fn build(config: &SandboxConfig) -> LinuxBackend {
    LinuxBackend::new(config.clone()).expect("backend")
}

#[track_caller]
#[expect(
    clippy::panic,
    reason = "a policy that compiles when it must not is a test failure"
)]
fn expect_refused(config: &SandboxConfig, because: &str) {
    match LinuxBackend::new(config.clone()) {
        Err(Error::Unsupported(reason)) => assert!(
            reason.contains("durable"),
            "expected a durability refusal, got: {reason}"
        ),
        Err(other) => panic!("expected Unsupported, got {other:?}"),
        Ok(_) => panic!("{because}"),
    }
}

/// A deny buried under a directory the sandbox may rename cannot be enforced
/// beyond the life of the backend: the child moves the directory aside, leaves
/// a decoy at the old name, and the *next run* of the same policy masks the
/// decoy. The shape is refused instead of being silently unenforceable later.
#[test]
fn write_deny_beneath_a_movable_directory_is_refused() {
    let tmp = TempDir::new().unwrap();
    let vault = tmp.path().join("vault");
    let locked = vault.join("locked");
    std::fs::create_dir_all(&locked).unwrap();

    let mut config = common::base();
    config.fs.extend([
        FsAccess::ReadAllow(tmp.path().into()),
        FsAccess::WriteAllow(tmp.path().into()),
        // `vault` sits inside the write-allowed root, so the sandbox can move it.
        FsAccess::WriteDeny(locked),
    ]);

    expect_refused(
        &config,
        "a deny under a sandbox-movable directory must not compile",
    );
}

/// The remedy the refusal suggests: deny write on the intermediate directory
/// too. That makes it a mount point, and renaming a mount point fails with
/// `EBUSY`, so nothing on the way to the deny can be relocated — and the deny
/// therefore still holds after the sandbox is torn down and rebuilt.
#[test]
fn denying_the_directory_above_makes_the_deny_durable() {
    if !enforced() {
        return;
    }

    let tmp = TempDir::new().unwrap();
    let vault = tmp.path().join("vault");
    let locked = vault.join("locked");
    std::fs::create_dir_all(&locked).unwrap();
    let precious = locked.join("precious.txt");
    std::fs::write(&precious, b"original").unwrap();
    let sibling = tmp.path().join("sibling");
    std::fs::create_dir(&sibling).unwrap();

    let mut config = common::base();
    config.fs.extend([
        FsAccess::ReadAllow(tmp.path().into()),
        FsAccess::WriteAllow(tmp.path().into()),
        FsAccess::WriteDeny(vault.clone()),
        FsAccess::WriteDeny(locked.clone()),
    ]);
    let session = build(&config);

    assert!(
        !run(&session, &["write-file", precious.to_str().unwrap()]),
        "the deny is enforced"
    );

    // The child cannot move the masked directory out of the way...
    assert!(
        !run(
            &session,
            &[
                "rename-file",
                vault.to_str().unwrap(),
                tmp.path().join("vault-real").to_str().unwrap(),
            ],
        ),
        "the masked directory is a mount point and cannot be renamed"
    );
    // ...and this control shows why that matters: renaming is otherwise
    // granted here, so the refusal above is the mount boundary (EBUSY), not
    // Landlock withholding `Refer`.
    assert!(
        run(
            &session,
            &[
                "rename-file",
                sibling.to_str().unwrap(),
                tmp.path().join("sibling2").to_str().unwrap(),
            ],
        ),
        "control: unmasked directories under the write grant are renameable"
    );
    // The two-step redirect fails at its first syscall for the same reason.
    assert!(
        !run(
            &session,
            &[
                "redirect-path",
                vault.to_str().unwrap(),
                tmp.path().join("vault-real").to_str().unwrap(),
                sibling.to_str().unwrap(),
            ],
        ),
        "the child cannot redirect the masked directory"
    );

    // The sandbox exits; the user comes back and rebuilds the same policy.
    drop(session);
    let next_day = build(&config);
    assert!(
        !run(&next_day, &["write-file", precious.to_str().unwrap()]),
        "the deny must still hold after a cold restart"
    );
    assert_eq!(
        std::fs::read(&precious).unwrap(),
        b"original",
        "the protected file is untouched"
    );
}

/// The same defect on the allow side: an allow root nested inside a
/// write-allowed directory can be swapped for a symlink between runs, and the
/// next run would issue its Landlock grant over whatever the name then points
/// at. Refused for the same reason.
#[test]
fn allow_root_inside_a_writable_directory_is_refused() {
    let tmp = TempDir::new().unwrap();
    let work = tmp.path().join("work");
    let sub = work.join("sub");
    std::fs::create_dir_all(&sub).unwrap();

    let mut config = common::base();
    config
        .fs
        .extend([FsAccess::ReadAllow(sub), FsAccess::WriteAllow(work)]);

    expect_refused(
        &config,
        "an allow root the sandbox can rename must not compile",
    );
}

/// The check must not reject the shapes people actually write. A deny directly
/// beneath its write-allowed root is durable: moving the root needs rights on
/// the root's parent, which the policy never grants.
#[test]
fn ordinary_project_shapes_stay_accepted() {
    if !enforced() {
        return;
    }

    let tmp = TempDir::new().unwrap();
    let project = tmp.path().join("project");
    let git = project.join(".git");
    let env = project.join(".env");
    std::fs::create_dir_all(&git).unwrap();
    std::fs::write(&env, b"SECRET=1").unwrap();
    std::fs::write(git.join("HEAD"), b"ref: refs/heads/main").unwrap();

    let mut config = common::base();
    config.fs.extend([
        FsAccess::ReadAllow(project.clone()),
        FsAccess::WriteAllow(project.clone()),
        FsAccess::WriteDeny(git.clone()),
        FsAccess::WriteDeny(env.clone()),
    ]);
    let backend = build(&config);

    assert!(
        run(
            &backend,
            &["write-file", project.join("src.rs").to_str().unwrap()]
        ),
        "the project is writable"
    );
    assert!(
        !run(
            &backend,
            &["write-file", git.join("HEAD").to_str().unwrap()]
        ),
        "the .git deny is enforced"
    );
    assert!(
        !run(&backend, &["write-file", env.to_str().unwrap()]),
        "the .env deny is enforced"
    );
}

/// The in-process pins are still what make a live backend safe, and they are
/// checked even against changes the sandbox itself could not make. Redirecting
/// a mask target out of band must fail the spawn closed rather than mask the
/// wrong inode.
#[test]
fn a_mask_target_swapped_out_of_band_fails_the_spawn_closed() {
    if !enforced() {
        return;
    }

    let tmp = TempDir::new().unwrap();
    let locked = tmp.path().join("locked");
    std::fs::create_dir(&locked).unwrap();
    let precious = locked.join("precious.txt");
    std::fs::write(&precious, b"original").unwrap();

    let mut config = common::base();
    config.fs.extend([
        FsAccess::ReadAllow(tmp.path().into()),
        FsAccess::WriteAllow(tmp.path().into()),
        FsAccess::WriteDeny(locked.clone()),
    ]);
    let backend = build(&config);
    assert!(
        !run(&backend, &["write-file", precious.to_str().unwrap()]),
        "control: the deny is enforced"
    );

    // Not reachable from inside the sandbox — `locked` is a mount point during
    // every spawn — but a concurrent host process could do this.
    std::fs::rename(&locked, tmp.path().join("locked-real")).unwrap();
    std::fs::create_dir(&locked).unwrap();

    match backend.spawn(common::probe(&["write-file", precious.to_str().unwrap()])) {
        Err(Error::Spawn(err)) => assert_eq!(
            err.kind(),
            std::io::ErrorKind::PermissionDenied,
            "a mask target that stopped naming its compiled inode fails closed"
        ),
        Err(other) => panic!("expected a refused spawn, got {other:?}"),
        Ok(_) => panic!("the spawn masked an inode the policy never compiled"),
    }
}

/// Landlock grants are held as descriptors opened at construction, so
/// redirecting an allow root's *name* out of band does not re-point the grant.
#[test]
fn an_allow_root_swapped_out_of_band_keeps_confining_its_pinned_inode() {
    if !enforced() {
        return;
    }

    let tmp = TempDir::new().unwrap();
    let sub = tmp.path().join("sub");
    let secret_dir = tmp.path().join("secret-dir");
    std::fs::create_dir(&sub).unwrap();
    std::fs::create_dir(&secret_dir).unwrap();
    std::fs::write(sub.join("readable.txt"), b"readable").unwrap();
    let secret = secret_dir.join("secret.txt");
    std::fs::write(&secret, b"TOPSECRET").unwrap();

    let mut config = common::base();
    config.fs.extend([FsAccess::ReadAllow(sub.clone())]);
    let backend = build(&config);

    assert!(
        run(
            &backend,
            &["read-file", sub.join("readable.txt").to_str().unwrap()]
        ),
        "control: the allow root is readable"
    );
    assert!(
        !run(&backend, &["read-file", secret.to_str().unwrap()]),
        "control: the secret is outside the policy"
    );

    let moved = tmp.path().join("sub-real");
    std::fs::rename(&sub, &moved).unwrap();
    std::os::unix::fs::symlink(&secret_dir, &sub).unwrap();

    assert!(
        !run(&backend, &["read-file", secret.to_str().unwrap()]),
        "the grant must not follow the redirected name"
    );
    assert!(
        run(
            &backend,
            &["read-file", moved.join("readable.txt").to_str().unwrap()]
        ),
        "the grant still covers the inode it was compiled against"
    );
}

/// The hard-link escape originally hypothesized against these masks does not
/// work, and this pins down why: `link(2)` returns `EXDEV` across mount points
/// and every mask is a mount point. The refusal is the mount boundary, not
/// Landlock withholding `Refer` — the same link *within* the allowed tree is
/// permitted.
#[test]
fn hardlink_out_of_a_mask_is_refused_by_the_kernel() {
    if !enforced() {
        return;
    }

    let tmp = TempDir::new().unwrap();
    let locked = tmp.path().join("locked");
    let writable = tmp.path().join("writable");
    std::fs::create_dir(&locked).unwrap();
    std::fs::create_dir(&writable).unwrap();
    let precious = locked.join("precious.txt");
    std::fs::write(&precious, b"original").unwrap();
    let ordinary = writable.join("ordinary.txt");
    std::fs::write(&ordinary, b"ordinary").unwrap();

    let mut config = common::base();
    config.fs.extend([
        FsAccess::ReadAllow(tmp.path().into()),
        FsAccess::WriteAllow(tmp.path().into()),
        FsAccess::WriteDeny(locked),
    ]);
    let backend = build(&config);

    assert!(
        !run(
            &backend,
            &[
                "link-file",
                precious.to_str().unwrap(),
                writable.join("escape.txt").to_str().unwrap(),
            ],
        ),
        "linking out of the mask is refused, so the file keeps one name"
    );
    assert_eq!(
        std::fs::read(&precious).unwrap(),
        b"original",
        "the write-denied file is untouched"
    );
    assert!(
        run(
            &backend,
            &[
                "link-file",
                ordinary.to_str().unwrap(),
                writable.join("second-name.txt").to_str().unwrap(),
            ],
        ),
        "control: hard links inside the allowed tree are granted"
    );
}
