//! Opted-in sandboxes (`linux_audit_denials`) carry guardrail's audit
//! personality marker, cannot clear it, and are refused on a host that will
//! not let them carry it. Sandboxes that did not opt in are untouched.

#![cfg(target_os = "linux")]

use std::collections::BTreeMap;

use guardrail_core::{Backend, Error, FsAccess, SandboxConfig};
use guardrail_linux::LinuxBackend;
use seccompiler::{BpfProgram, SeccompAction, SeccompFilter};
use tempfile::TempDir;

mod common;

const MARKER: libc::c_int = 0x0300_0000;

fn audited() -> SandboxConfig {
    let mut config = common::base();
    config.linux_audit_denials = true;
    config
}

/// Run the probe under `config` and return its exit code.
fn exit_code(config: &SandboxConfig, args: &[&str]) -> Option<i32> {
    let mut child = LinuxBackend::new(config.clone())
        .expect("backend")
        .spawn(common::probe(args))
        .expect("spawn");
    child.wait().expect("wait").code()
}

#[test]
fn audited_child_carries_the_marker() {
    // The probe checks after its own execve, so this also proves the marker
    // survives exec and that the pin leaves the personality query alone.
    assert_eq!(
        exit_code(&audited(), &["personality-marker"]),
        Some(0),
        "an opted-in sandbox must carry the audit personality marker"
    );
}

#[test]
fn default_child_is_not_marked() {
    assert_eq!(
        exit_code(&common::base(), &["personality-marker"]),
        Some(3),
        "a sandbox that did not opt in must not be marked"
    );
}

#[test]
fn audited_child_cannot_clear_the_marker() {
    // No marker bit, only SHORT_INODE, only WHOLE_SECONDS.
    for persona in ["0", "1000000", "2000000"] {
        assert_eq!(
            exit_code(&audited(), &["personality-set", persona]),
            Some(3),
            "personality({persona}) drops a marker bit and must fail with EPERM"
        );
    }
}

#[test]
fn audited_child_may_change_other_personality_bits() {
    // 0x3040000 = marker | ADDR_NO_RANDOMIZE, what a debugger sets.
    assert_eq!(
        exit_code(&audited(), &["personality-set", "3040000"]),
        Some(0),
        "a personality change that keeps the marker must stay allowed"
    );
}

#[test]
fn default_child_may_change_personality() {
    assert_eq!(
        exit_code(&common::base(), &["personality-set", "0"]),
        Some(0),
        "personality(2) must stay unrestricted when the option is off"
    );
}

#[test]
fn spawning_does_not_mark_the_host_process() {
    exit_code(&audited(), &["personality-marker"]);

    // SAFETY: personality with 0xffffffff only queries the value.
    let persona = unsafe { libc::personality(0xffff_ffff) };
    assert_eq!(
        persona & MARKER,
        0,
        "the marker is set after fork and must not leak into the host process"
    );
}

#[test]
fn audited_sandbox_still_denies_writes() {
    if !common::landlock_enforced() {
        eprintln!("skipping: Landlock not enforced on this kernel");
        return;
    }

    // A denied write from a marked process: the event a host audit rule
    // keyed on the marker records.
    let tmp = TempDir::new().expect("tempdir");
    let target = tmp.path().join("out.txt");
    let mut config = audited();
    config.fs.push(FsAccess::ReadAllow(tmp.path().into()));
    assert_eq!(
        exit_code(
            &config,
            &["write-file", target.to_str().expect("utf-8 path")]
        ),
        Some(3),
        "enforcement must be unchanged in an opted-in sandbox"
    );
}

#[test]
fn construction_fails_when_the_host_refuses_personality() {
    // Stand in for a host that locks personality(2) (systemd
    // LockPersonality=): refuse it with EPERM on one disposable thread. The
    // probe child that `LinuxBackend::new` forks inherits the filter; the
    // other test threads never see it.
    std::thread::spawn(|| {
        let filter = SeccompFilter::new(
            BTreeMap::from([(libc::SYS_personality, vec![])]),
            SeccompAction::Allow,
            SeccompAction::Errno(libc::EPERM as u32),
            std::env::consts::ARCH.try_into().expect("arch"),
        )
        .expect("filter");
        let program: BpfProgram = filter.try_into().expect("program");
        seccompiler::apply_filter(&program).expect("install");

        assert!(
            matches!(LinuxBackend::new(audited()), Err(Error::Unsupported(_))),
            "an opted-in backend must refuse a host that refuses the marker"
        );
        assert!(
            LinuxBackend::new(common::base()).is_ok(),
            "a backend that did not opt in must not touch personality(2)"
        );
    })
    .join()
    .expect("probe thread");
}
