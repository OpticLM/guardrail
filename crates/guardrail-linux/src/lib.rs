//! Linux backend for `guardrail`.
//!
//! Applies confinement entirely in-process inside [`std::process::Command`]'s
//! `pre_exec` hook: resource limits via `setrlimit`, plus Landlock filesystem
//! rules and seccomp-BPF filters for network and IPC. No external sandboxing
//! binary is used.
//!
//! Unless the network policy is `Full`, the `io_uring_*` syscalls fail with
//! `ENOSYS`: ring-submitted operations (`IORING_OP_SOCKET`,
//! `IORING_OP_CONNECT`, `IORING_OP_BIND`, ...) are not syscalls, so an open
//! ring would bypass the network rules. Runtimes that probe io_uring for file
//! I/O see a kernel without io_uring and fall back to plain syscalls.
//!
//! Fails closed: constructing a [`LinuxBackend`] returns `Error::Unsupported`
//! when Landlock enforcement or the seccomp action-availability probe fails;
//! spawning aborts if actual filter installation fails. Probe known
//! incompatibilities up front with `LinuxBackend::probe_support()`. The
//! Landlock probe verifies enforcement on a disposable thread. The seccomp
//! probe only queries whether the kernel reports the filters' `Trap` and
//! `Errno` actions; a successful probe does not prove that an ambient sandbox
//! will permit installing the filters.

#![cfg(target_os = "linux")]

mod backend;
mod fs;
mod rlimit;
mod seccomp;
mod support;

pub use backend::LinuxBackend;
