#![cfg(target_os = "linux")]

//! Capability-probe intent tests: `probe_support` reports known capability
//! failures, and backend construction fails closed when a probe fails.

use guardrail_core::{Backend, Error};
use guardrail_linux::LinuxBackend;

mod common;

#[test]
fn probe_support_reports_capability_failures_as_unsupported() {
    match LinuxBackend::probe_support() {
        Ok(()) => {}
        Err(Error::Unsupported(_)) => {}
        Err(other) => panic!("probe_support must fail with Unsupported, got: {other:?}"),
    }
}

#[test]
fn backend_construction_fails_closed_without_kernel_support() {
    let result = LinuxBackend::new(common::base());
    match (LinuxBackend::probe_support(), result) {
        (Ok(()), Ok(_)) => {}
        (Ok(()), Err(e)) => panic!("backend must build on a supported kernel: {e:?}"),
        (Err(_), Err(Error::Unsupported(_))) => {}
        (Err(_), Err(other)) => panic!(
            "backend construction must fail with Unsupported on an unsupported \
             kernel, got: {other:?}"
        ),
        (Err(reason), Ok(_)) => {
            panic!("backend construction must fail closed on an unsupported kernel ({reason})")
        }
    }
}
