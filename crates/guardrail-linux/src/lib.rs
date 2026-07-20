//! Linux backend for `guardrail`.
//!
//! Applies confinement entirely in-process around [`std::process::Command`]'s
//! `pre_exec` hook: resource limits via `setrlimit`, plus Landlock filesystem
//! rules and seccomp-BPF filters for network and IPC. Policies and all
//! host-path Landlock rules are built in the parent; the post-fork child only
//! issues raw syscalls (`prctl`, `unshare`, `mount`, `setrlimit`,
//! `landlock_add_rule`, `landlock_restrict_self`, `close_range`, `seccomp`)
//! over parent-prepared data — the async-signal-safe subset the `pre_exec`
//! contract requires when the parent is multithreaded (e.g. Node via
//! `guardrail-napi`). Every parent file descriptor above stderr is marked
//! close-on-exec, so only stdio
//! crosses into the child — policies cannot revoke access to descriptors
//! that are already open, so inheriting one would bypass them. No external
//! sandboxing binary is used.
//!
//! # Deny rules beneath allowed parents
//!
//! Landlock rules are additive grants, so a policy such as `allow(root)` then
//! `deny(root/secret)` is enforced by a second layer: the allowed parent is
//! granted wholesale (covering entries created at any later time), and each
//! deny boundary is overmounted with a mask — an empty read-only tmpfs or
//! file for read denies, a read-only or noexec self-bind for write/execute
//! denies — inside a per-spawn unprivileged user + mount namespace whose
//! propagation is private to the child. Mounts attach to the directory
//! itself, so the ordered policy stays live no matter when files appear on
//! either side of the boundary, and a second namespace boundary locks the
//! masks (`MNT_LOCKED`) against children permitted to create namespaces of
//! their own. See `src/ns.rs` for the mechanism.
//!
//! # Per-spawn IPC isolation
//!
//! Every spawn enters a fresh IPC namespace, isolating its SysV shared
//! memory, semaphore, and message-queue identifiers and its POSIX message
//! queues from the host and from other spawns. POSIX shared memory and named
//! semaphores are filesystem-backed instead, so `/dev/shm` is overmounted
//! with a private 64 MiB tmpfs using `nosuid,nodev,noexec`. The child receives
//! an internal Landlock read/write/create/remove grant for that private mount;
//! granting the host `/dev/shm` in [`guardrail_core::FsAccess`] still cannot
//! reveal host objects because the host mount has already been hidden.
//!
//! This isolation applies on every Landlock ABI supported by this backend; it
//! is not a best-effort ABI-dependent feature. It needs unprivileged user
//! namespaces, so when the host forbids them (Debian's
//! `kernel.unprivileged_userns_clone=0`, Ubuntu 24.04's
//! `apparmor_restrict_unprivileged_userns=1`, `user.max_user_namespaces=0`),
//! constructing a backend fails with a precise `Error::Unsupported` instead
//! of approximating.
//!
//! The same mandatory user + mount namespace contains deny-under-allow mount
//! masks. One filesystem-policy shape is rejected on any host: denying read
//! on a path while write or execute stays allowed there — a hidden path
//! cannot remain writable.
//!
//! Under `IpcPolicy::Strict` (the default), creating a Unix-domain socket —
//! pathname or abstract — fails with `EAFNOSUPPORT`, so the child cannot reach
//! local services (D-Bus, container engines, agent sockets) or proxy data
//! through them. Unix datagram `socketpair`s fail too because their endpoints
//! can be redirected to named sockets. The graceful errno lets tools that
//! merely probe optional sockets (nscd, syslog, ssh-agent) fall back;
//! connection-oriented `socketpair`s created by the child keep working.
//!
//! # OutboundOnly and Unix-domain servers
//!
//! `NetworkPolicy::OutboundOnly` restricts IP servers, but seccomp cannot see
//! a socket fd's family at `bind`/`listen` time, so how that restriction is
//! enforced follows the IPC policy. Under `IpcPolicy::Strict` no Unix-domain
//! socket can exist, so family-blind whole-syscall traps (SIGSYS) are sound
//! and used.
//! Under `IpcPolicy::Relaxed` — which permits Unix-domain servers — the
//! denial moves to a second Landlock ruleset handling `BindTcp` with no
//! rules: binding a TCP socket to any port fails with `EACCES` while outbound
//! `connect` and Unix-domain `bind`/`listen` are untouched. This requires
//! Landlock ABI v4 (Linux 6.7+); on older kernels constructing a backend for
//! that policy combination fails with `Error::Unsupported` instead of
//! silently narrowing the contract. Two residuals of what the kernel can
//! express today remain under that combination: `listen(2)` on an unbound
//! TCP socket autobinds an ephemeral port without passing the LSM bind hook,
//! and UDP bind is not yet covered (Landlock gained UDP rights in ABI v10,
//! not yet exposed by the `landlock` crate). Compose with `IpcPolicy::Strict`
//! when the child must not serve anything at all.
//!
//! Unless the network policy is `Full` and the IPC policy is `Relaxed`, the
//! `io_uring_*` syscalls fail with `ENOSYS`: ring-submitted operations
//! (`IORING_OP_SOCKET`, `IORING_OP_CONNECT`, `IORING_OP_BIND`, ...) are not
//! syscalls, so an open ring would bypass the socket rules. Runtimes that
//! probe io_uring for file I/O see a kernel without io_uring and fall back to
//! plain syscalls.
//!
//! # Kernel attack surface and threat model
//!
//! Kernel interfaces no shell tool legitimately calls are denied regardless
//! of policy: kernel code loading (`kexec_*`, module loaders), the kernel
//! keyring (`add_key`, `request_key`, `keyctl`), host-state interference
//! (`reboot`, `swapon`/`swapoff`, `acct`), and the probed-by-tooling trio
//! `bpf`, `perf_event_open`, and `userfaultfd` (denied with `EPERM`, the
//! errno a hardened kernel gives unprivileged callers, so tools fall back
//! gracefully).
//!
//! Under `UserNamespacePolicy::Deny` (the default), creating or joining
//! namespaces is denied too — `unshare(CLONE_NEWUSER)`, `clone(CLONE_NEWUSER)`,
//! and `setns` with `EPERM`, `clone3` with `ENOSYS` so runtimes fall back to
//! the inspectable `clone` — along with the mount machinery (`mount`,
//! `pivot_root`, `chroot`, the new mount API), which unprivileged code can
//! only exercise inside a user namespace it owns. Set
//! `SandboxConfig::linux_user_namespaces` to `Allow` only when the child runs
//! its own nested sandbox (Chromium/Electron, bubblewrap, rootless
//! containers).
//!
//! The result is policy enforcement and harm reduction against opportunistic
//! and most deliberate misbehavior, not Chromium-grade isolation: the child
//! still shares the host kernel, and the seccomp layer is a denylist over a
//! default-allow filter, so a kernel vulnerability reachable through ordinary
//! syscalls remains reachable. Run code that is hostile *by design* in a
//! virtual machine instead.
//!
//! Fails closed: constructing a [`LinuxBackend`] returns `Error::Unsupported`
//! when Landlock enforcement or the seccomp action-availability probe fails;
//! spawning aborts if actual filter installation fails. The kernel floor is
//! Landlock ABI v2 (Linux 5.19+): write grants carry Landlock's `Refer`
//! right, so renaming or hard-linking across write-allowed directories works
//! (subject to the kernel's `Refer` constraint that a move may not grant the
//! file more access than it had), and older kernels — where such operations
//! always fail with `EXDEV` — are rejected instead of silently narrowing the
//! `WriteAllow` contract. Probe known
//! incompatibilities up front with `LinuxBackend::probe_support()`. The
//! Landlock probe verifies enforcement on a disposable thread. The seccomp
//! probe only queries whether the kernel reports the filters' `Trap` and
//! `Errno` actions; a successful probe does not prove that an ambient sandbox
//! will permit installing the filters.

#![cfg(target_os = "linux")]

mod backend;
mod fs;
mod net;
mod ns;
mod rlimit;
mod seccomp;
mod support;

pub use backend::LinuxBackend;
