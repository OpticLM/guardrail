//! Linux backend for `guardrail`.
//!
//! Applies confinement entirely in-process around [`std::process::Command`]'s
//! `pre_exec` hook: resource limits via `setrlimit`, plus Landlock filesystem
//! rules and seccomp-BPF filters for network and IPC. Policies are compiled
//! and the Landlock ruleset is fully built in the parent; the post-fork child
//! only issues raw syscalls (`prctl`, `setrlimit`, `landlock_restrict_self`,
//! `close_range`, `seccomp`) over parent-prepared data — the
//! async-signal-safe subset the `pre_exec` contract requires when the parent
//! is multithreaded (e.g. Node via `guardrail-napi`). Every parent file
//! descriptor above stderr is marked close-on-exec, so only stdio crosses
//! into the child — policies cannot revoke access to descriptors that are
//! already open, so inheriting one would bypass them. No external sandboxing
//! binary is used.
//!
//! Under `IpcPolicy::Strict` (the default), creating a Unix-domain socket —
//! pathname or abstract — fails with `EAFNOSUPPORT`, so the child cannot reach
//! local services (D-Bus, container engines, agent sockets) or proxy data
//! through them. Unix datagram `socketpair`s fail too because their endpoints
//! can be redirected to named sockets. The graceful errno lets tools that
//! merely probe optional sockets (nscd, syslog, ssh-agent) fall back;
//! connection-oriented `socketpair`s created by the child keep working.
//!
//! Unless the network policy is `Full` and the IPC policy is `Relaxed`, the
//! `io_uring_*` syscalls fail with `ENOSYS`: ring-submitted operations
//! (`IORING_OP_SOCKET`, `IORING_OP_CONNECT`, `IORING_OP_BIND`, ...) are not
//! syscalls, so an open ring would bypass the socket rules. Runtimes that
//! probe io_uring for file I/O see a kernel without io_uring and fall back to
//! plain syscalls.
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
