//! macOS backend support for `guardrail`.
//!
//! Profile generation is pure Rust; Seatbelt application is native macOS.
//!
//! # Tips: common macOS runtime grants
//!
//! Guardrail generates only the rules you explicitly declare — no implicit
//! startup allowances. When sandboxing a macOS binary under Seatbelt with
//! `(deny default)`, you often need additional grants for the runtime
//! environment. The following patterns are common:
//!
//! **Filesystem**
//! - The root volume metadata (`/`) and `/var` for basic file-system probing.
//! - `/System/Cryptexes/OS` and `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld`
//!   for the dynamic linker on Apple Silicon.
//! - `/dev/dtracehelper` if the process or its runtime uses DTrace (with both
//!   `file-read-data`, `file-write-data`, and `file-ioctl` permissions).
//!
//! **Sysctl**
//! - `kern.bootargs`, `kern.osvariant_status`, `hw.ephemeral_storage`,
//!   `hw.pagesize_compat`, `machdep.ptrauth_enabled` are commonly queried
//!   by the runtime and well-known libraries.
//! - `security.mac.lockdown_mode_state` is read by some system frameworks.
//!
//! Use `.fs([FsAccess::ReadAllow(...), FsAccess::ExecuteAllow(...)])` for
//! binary and dylib paths, and grant sysctl access via a custom `.sb` profile
//! import or a manual `(allow sysctl-read (sysctl-name "kern.bootargs"))` rule
//! in your profile. Set `darwin_sandbox_profiles` on `SandboxConfig` for the
//! custom-profile escape hatch.

#[cfg(target_os = "macos")]
mod backend;
#[cfg(target_os = "macos")]
mod profile;
#[cfg(target_os = "macos")]
mod rlimit;
#[cfg(target_os = "macos")]
mod seatbelt;

#[cfg(target_os = "macos")]
pub use backend::MacosBackend;
