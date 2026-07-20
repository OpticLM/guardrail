//! macOS backend support for `guardrail`.
//!
//! Profile generation is pure Rust. The fork child performs only
//! async-signal-safe setup, then execs `/usr/bin/sandbox-exec`; Seatbelt
//! profile parsing and application happen in that fresh, single-threaded
//! launcher process before it execs the requested command.
//!
//! # Security: imported profiles are authoritative
//!
//! Profiles named by [`guardrail_core::SandboxConfig::darwin_sandbox_profiles`]
//! are emitted before Guardrail's generated `(deny default)` and portable
//! filesystem and network rules. An `allow` in an imported profile can
//! therefore grant access absent from the portable policy, including filesystem
//! paths omitted from [`guardrail_core::SandboxConfig::fs`]. The generated
//! rules do not narrow or revoke that access.
//!
//! Treat imported profiles and all of their transitive imports as trusted
//! sandbox policy. Prefer portable [`guardrail_core::FsAccess`] rules for
//! filesystem access, keep custom imports narrowly scoped to operations such as
//! required sysctls and Mach lookups, and store imported files outside paths
//! writable by the sandboxed child. Broad built-in profiles can import further
//! rules and should be audited for the target macOS release before use.
//!
//! # Security: policy path requirements
//!
//! Paths embedded in the generated profile — [`guardrail_core::FsAccess`] rule
//! paths and [`guardrail_core::SandboxConfig::darwin_sandbox_profiles`] import
//! paths — must be absolute, valid UTF-8, and free of control characters.
//! Backend construction fails closed with
//! [`guardrail_core::Error::Confinement`] on any other path, so untrusted path
//! strings cannot change the structure of the generated SBPL.
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
//! **IPC**
//! - IPC confinement comes from `(deny default)`, which denies Mach bootstrap lookups
//!   (`mach-lookup`), POSIX and SysV IPC (`ipc-posix-*`, `ipc-sysv-*`), and
//!   Unix-domain socket connections. Grant exactly what a workload needs
//!   through an imported `.sb` profile, e.g.
//!   `(allow mach-lookup (global-name "..."))`.
//! - `NetworkPolicy::OutboundOnly` and `Full` emit an unqualified
//!   `(allow network-outbound)`, which also permits `connect` to local
//!   Unix-domain sockets — Seatbelt treats those as network operations.
//!
//! Add `FsAccess::ReadAllow(...)` and `FsAccess::ExecuteAllow(...)` rules to
//! [`guardrail_core::SandboxConfig::fs`] for binary and dylib paths, and grant
//! sysctl access via a custom `.sb` profile import or a manual
//! `(allow sysctl-read (sysctl-name "kern.bootargs"))` rule in your profile.
//! Set `darwin_sandbox_profiles` on `SandboxConfig` for the custom-profile
//! escape hatch.

#![cfg(target_os = "macos")]

mod backend;
mod profile;
mod rlimit;
mod seatbelt;

pub use backend::MacosBackend;
