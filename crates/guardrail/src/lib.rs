//! Cross-platform facade for `guardrail`.
//!
//! This crate re-exports the platform-agnostic policy and process types from
//! `guardrail-core`, plus [`PlatformBackend`], an alias for the backend matching
//! the current Cargo target. `PlatformBackend::probe_support()` (from
//! [`Backend`]) performs the platform's advisory capability probe.
//!
//! # Platform capability matrix
//!
//! Each [`SandboxConfig`] field is enforced by a different mechanism per
//! backend; a field marked *ignored* is an honest no-op on that platform.
//!
//! | Field | Linux | macOS | Windows |
//! |---|---|---|---|
//! | `fs` | Landlock | Seatbelt profile | AppContainer + additive ACL grants |
//! | `network` | seccomp socket-family filter | Seatbelt network rules | AppContainer capabilities |
//! | `limits` | `setrlimit` | `setrlimit` | Job Object |
//! | `env` | cleared, then set | cleared, then set | cleared, then set |
//! | `linux_ipc` | seccomp (SysV/POSIX IPC, `AF_UNIX`, ptrace) | ignored — IPC follows generated/imported Seatbelt rules; network grants can permit Unix-socket connections | ignored — AppContainer baseline isolation applies independently; see backend limits |
//! | `linux_user_namespaces` | seccomp (namespace creation/joining + mount machinery) | ignored — no equivalent unprivileged facility | ignored — no equivalent unprivileged facility |
//! | `darwin_sandbox_profiles` | ignored | trusted `.sb` policy imports that can grant access absent from `fs`/`network` | ignored |
//! | `windows_cache_namespace` | ignored | ignored | AppContainer/ACL cache key |
//!
//! See each backend crate's documentation for the platform's exact semantics
//! and limits.

pub use guardrail_core::*;

#[cfg(target_os = "linux")]
pub use guardrail_linux::LinuxBackend as PlatformBackend;

#[cfg(target_os = "macos")]
pub use guardrail_macos::MacosBackend as PlatformBackend;

#[cfg(windows)]
pub use guardrail_windows::WindowsBackend as PlatformBackend;

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
compile_error!("guardrail supports Linux, macOS, and Windows targets");
