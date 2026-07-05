//! Cross-platform facade for `guardrail`.
//!
//! This crate re-exports the platform-agnostic policy and process types from
//! `guardrail-core`, plus [`PlatformBackend`], an alias for the backend matching
//! the current Cargo target.

pub use guardrail_core::*;

#[cfg(target_os = "linux")]
pub use guardrail_linux::LinuxBackend as PlatformBackend;

#[cfg(target_os = "macos")]
pub use guardrail_macos::MacosBackend as PlatformBackend;

#[cfg(windows)]
pub use guardrail_windows::WindowsBackend as PlatformBackend;

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
compile_error!("guardrail supports Linux, macOS, and Windows targets");
