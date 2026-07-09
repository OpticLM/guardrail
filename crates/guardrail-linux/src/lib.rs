//! Linux backend for `guardrail`.
//!
//! Applies confinement entirely in-process inside [`std::process::Command`]'s
//! `pre_exec` hook: resource limits via `setrlimit`, plus Landlock filesystem
//! rules and a seccomp-BPF filter for network and IPC. No external sandboxing
//! binary is used.

#![cfg(target_os = "linux")]

mod backend;
mod fs;
mod rlimit;
mod seccomp;

pub use backend::LinuxBackend;
