//! macOS backend support for `guardrail`.
//!
//! Profile generation is platform-independent and tested on Linux. Native
//! Seatbelt application is added in plan 009.

#[allow(dead_code)]
mod profile;

#[cfg(test)]
mod tests {
    use guardrail_core::SandboxBuilder;

    #[test]
    fn crate_smoke_test_builds_a_default_config() {
        let config = SandboxBuilder::new().build();
        assert!(config.fs.is_empty());
    }
}
