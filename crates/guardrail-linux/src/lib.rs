//! Linux backend for `guardrail`.
//!
//! Applies confinement entirely in-process inside [`std::process::Command`]'s
//! `pre_exec` hook: resource limits via `setrlimit`, plus Landlock filesystem
//! rules and a seccomp-BPF filter for network and IPC. No external sandboxing
//! binary is used.

#[cfg(not(target_os = "linux"))]
compile_error!("guardrail-linux can only be compiled for Linux targets");

#[cfg(target_os = "linux")]
mod backend;

#[cfg(target_os = "linux")]
mod fs;
#[cfg(target_os = "linux")]
mod rlimit;
#[cfg(target_os = "linux")]
mod seccomp;

#[cfg(target_os = "linux")]
pub use backend::LinuxBackend;
