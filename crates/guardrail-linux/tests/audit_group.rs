//! Sandboxes configured with `linux_audit_group` carry that supplementary
//! group, cannot drop it, and are refused on a host that cannot add it.
//!
//! Adding a group needs `CAP_SETGID`, so the tests that spawn a grouped
//! sandbox skip on an unprivileged host.

#![cfg(target_os = "linux")]

use std::collections::BTreeMap;

use guardrail_core::{Backend, Error, SandboxConfig, StdioMode};
use guardrail_linux::LinuxBackend;
use seccompiler::{BpfProgram, SeccompAction, SeccompFilter};

mod common;

/// Any group id works; it does not need an entry in `/etc/group`.
const GROUP: u32 = 4242;

fn grouped() -> SandboxConfig {
    let mut config = common::base();
    config.linux_audit_group = Some(GROUP);
    config
}

/// A backend for `config`, or `None` when this host cannot add groups.
#[expect(
    clippy::panic,
    reason = "an unexpected backend error invalidates the test harness"
)]
fn backend_or_skip(config: SandboxConfig) -> Option<LinuxBackend> {
    match LinuxBackend::new(config) {
        Ok(backend) => Some(backend),
        Err(Error::Unsupported(reason)) if reason.contains("CAP_SETGID") => {
            eprintln!("skipping: {reason}");
            None
        }
        Err(other) => panic!("unexpected backend error: {other:?}"),
    }
}

/// The supplementary groups of `pid` as the host sees them, which is where
/// the audit subsystem looks. Inside the sandbox's user namespace the audit
/// group has no mapping and shows as the overflow group.
fn host_view_of_groups(pid: u32) -> Vec<String> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).expect("status");
    status
        .lines()
        .find_map(|line| line.strip_prefix("Groups:"))
        .expect("Groups line")
        .split_whitespace()
        .map(str::to_owned)
        .collect()
}

#[test]
fn grouped_child_carries_the_audit_group() {
    let Some(backend) = backend_or_skip(grouped()) else {
        return;
    };
    let mut command = common::probe(&["hold"]);
    command.stdin = StdioMode::Piped;
    // `spawn` returns after the probe's execve, so this also proves the
    // group survives exec and the user-namespace setup.
    let mut child = backend.spawn(command).expect("spawn");

    let groups = host_view_of_groups(child.id());
    drop(child.take_stdin());
    assert_eq!(child.wait().expect("wait").code(), Some(0));
    assert!(
        groups.contains(&GROUP.to_string()),
        "the sandboxed child must carry the audit group, got {groups:?}"
    );
}

#[test]
fn grouped_child_cannot_drop_the_group() {
    let Some(backend) = backend_or_skip(grouped()) else {
        return;
    };
    let mut child = backend
        .spawn(common::probe(&["setgroups-empty"]))
        .expect("spawn");
    assert_eq!(
        child.wait().expect("wait").code(),
        Some(3),
        "setgroups(2) must fail with EPERM inside the sandbox"
    );
}

#[test]
fn audit_group_combines_with_the_personality_marker() {
    let mut config = grouped();
    config.linux_audit_denials = true;
    let Some(backend) = backend_or_skip(config) else {
        return;
    };
    let mut child = backend
        .spawn(common::probe(&["personality-marker"]))
        .expect("spawn");
    assert_eq!(
        child.wait().expect("wait").code(),
        Some(0),
        "the two markers are independent; setting both applies both"
    );
}

#[test]
fn spawning_does_not_change_the_host_groups() {
    let before = host_view_of_groups(std::process::id());
    if let Some(backend) = backend_or_skip(grouped()) {
        let mut child = backend
            .spawn(common::probe(&["setgroups-empty"]))
            .expect("spawn");
        child.wait().expect("wait");
    }
    assert_eq!(
        host_view_of_groups(std::process::id()),
        before,
        "the group is added after fork and must not leak into the host process"
    );
}

#[test]
fn construction_fails_when_the_host_cannot_add_groups() {
    // Stand in for a host process without CAP_SETGID: refuse setgroups(2)
    // with EPERM on one disposable thread. The probe child that
    // `LinuxBackend::new` forks inherits the filter; the other test threads
    // never see it.
    std::thread::spawn(|| {
        let filter = SeccompFilter::new(
            BTreeMap::from([(libc::SYS_setgroups, vec![])]),
            SeccompAction::Allow,
            SeccompAction::Errno(libc::EPERM as u32),
            std::env::consts::ARCH.try_into().expect("arch"),
        )
        .expect("filter");
        let program: BpfProgram = filter.try_into().expect("program");
        seccompiler::apply_filter(&program).expect("install");

        assert!(
            matches!(
                LinuxBackend::new(grouped()),
                Err(Error::Unsupported(reason)) if reason.contains("CAP_SETGID")
            ),
            "a backend with an audit group must refuse a host that cannot add it"
        );
        assert!(
            LinuxBackend::new(common::base()).is_ok(),
            "a backend without an audit group must not call setgroups(2)"
        );
    })
    .join()
    .expect("probe thread");
}
