//! Kernel-attack-surface and user-namespace policy enforcement.

#![cfg(target_os = "linux")]

use std::process::ExitStatus;

use guardrail_core::{Backend, SandboxCommand, SandboxConfig, UserNamespacePolicy};
use guardrail_linux::LinuxBackend;

mod common;

fn probe(args: &[&str]) -> SandboxCommand {
    common::probe(args)
}

fn status(config: &SandboxConfig, args: &[&str]) -> ExitStatus {
    let cmd = probe(args);
    let mut child = LinuxBackend::new(config.clone())
        .expect("backend")
        .spawn(cmd)
        .expect("spawn");
    child.wait().expect("wait")
}

fn allowed(config: &SandboxConfig, args: &[&str]) -> bool {
    status(config, args).success()
}

fn trapped(config: &SandboxConfig, args: &[&str]) -> bool {
    use std::os::unix::process::ExitStatusExt;
    status(config, args).signal() == Some(libc::SIGSYS)
}

#[test]
fn mount_is_trapped_by_default() {
    assert!(
        trapped(&common::base(), &["mount"]),
        "mount(2) must die with SIGSYS under the default policy"
    );
}

#[test]
fn mount_reaches_the_kernel_when_user_namespaces_are_allowed() {
    let mut config = common::base();
    config.linux_user_namespaces = UserNamespacePolicy::Allow;
    // The kernel still refuses the unprivileged call with a plain errno; the
    // probe exits 0 for any errno and only the sandbox's Trap kills it.
    assert!(
        allowed(&config, &["mount"]),
        "mount(2) must not be trapped under UserNamespacePolicy::Allow"
    );
}

#[test]
fn mount_setattr_is_trapped_by_default() {
    assert!(
        trapped(&common::base(), &["mount-setattr"]),
        "mount_setattr(2) must die with SIGSYS under the default policy"
    );
}

#[test]
fn mount_setattr_reaches_the_kernel_when_user_namespaces_are_allowed() {
    let mut config = common::base();
    config.linux_user_namespaces = UserNamespacePolicy::Allow;
    assert!(
        allowed(&config, &["mount-setattr"]),
        "mount_setattr(2) must not be trapped under UserNamespacePolicy::Allow"
    );
}

#[test]
fn kexec_load_is_trapped_at_both_user_namespace_levels() {
    for policy in [UserNamespacePolicy::Deny, UserNamespacePolicy::Allow] {
        let mut config = common::base();
        config.linux_user_namespaces = policy;
        assert!(
            trapped(&config, &["kexec-load"]),
            "kexec_load(2) must die with SIGSYS under {policy:?}"
        );
    }
}

#[test]
fn user_namespace_creation_is_denied_gracefully_by_default() {
    // Exit 3, not SIGSYS: the denial is Errno(EPERM) so sandbox-aware
    // programs probing user namespaces fall back instead of dying.
    assert_eq!(
        status(&common::base(), &["unshare-user"]).code(),
        Some(3),
        "unshare(CLONE_NEWUSER) must fail with an errno under the default policy"
    );
}

#[test]
fn user_namespace_creation_follows_an_allow_policy() {
    // Only provable on hosts that permit unprivileged user namespaces at all
    // (sysctls and LSM restrictions deny them with the same EPERM).
    if !std::process::Command::new(common::probe_path())
        .arg("unshare-user")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("run probe unsandboxed")
        .success()
    {
        eprintln!("skipping: host denies unprivileged user namespaces");
        return;
    }
    let mut config = common::base();
    config.linux_user_namespaces = UserNamespacePolicy::Allow;
    assert!(
        allowed(&config, &["unshare-user"]),
        "unshare(CLONE_NEWUSER) must succeed under UserNamespacePolicy::Allow"
    );
}

#[test]
fn bpf_is_denied_gracefully() {
    assert_eq!(
        status(&common::base(), &["bpf"]).code(),
        Some(3),
        "bpf(2) must fail with EPERM, not SIGSYS"
    );
}

#[test]
fn fork_survives_the_clone3_denial() {
    // clone3 is denied with ENOSYS under the default policy; glibc must fall
    // back to plain clone(2) for fork to keep working.
    assert!(
        allowed(&common::base(), &["fork"]),
        "fork must keep working while clone3 is denied"
    );
}
