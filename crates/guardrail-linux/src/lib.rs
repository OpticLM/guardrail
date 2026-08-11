//! Linux backend for `guardrail`.
//!
//! Applies confinement entirely in-process around [`std::process::Command`]'s
//! `pre_exec` hook: resource limits via `setrlimit`, plus Landlock filesystem
//! rules and seccomp-BPF filters for network and kernel attack surface.
//! Policies and all host-path Landlock rules are built in the parent; the post-fork child only
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
//! Every spawn enters a fresh IPC namespace, isolating its SysV shared-memory,
//! semaphore, and message-queue identifiers and its POSIX message queues from
//! the host and from other spawns. Because an inherited `mqueue` filesystem
//! remains associated with the IPC namespace in which it was mounted,
//! `/dev/mqueue` is overmounted again after namespace entry. POSIX shared
//! memory and named semaphores are filesystem-backed instead, so `/dev/shm` is
//! overmounted with a private 64 MiB tmpfs. Both mounts use
//! `nosuid,nodev,noexec`. The child receives internal Landlock
//! read/write/create/remove grants for these private IPC filesystems; granting
//! their host paths in [`guardrail_core::FsAccess`] still cannot reveal host
//! objects because the host mounts have already been hidden.
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
//! # Landlock ABI behavior
//!
//! Every spawn also enters its own Landlock domain for the IPC operations the
//! running kernel can mediate. Abstract-socket and signal scoping, pathname
//! sockets, and UDP bind are deliberately best-effort across ABI versions.
//! TCP bind is the exception:
//! `OutboundOnly` fails closed on ABI v2-v3 because that policy's explicit
//! bind guarantee cannot be enforced there.
//!
//! | Runtime Landlock ABI | `OutboundOnly` TCP bind | Abstract Unix sockets | Signals | Host-created pathname Unix sockets | `OutboundOnly` UDP bind |
//! | --- | --- | --- | --- | --- | --- |
//! | v2-v3 | unsupported: backend construction fails because explicit TCP bind cannot be denied | not scoped | not scoped | unrestricted; `linux_unix_sockets` is ignored without validation | not reached: `OutboundOnly` is unsupported |
//! | v4-v5 | every explicit bind denied; `listen` on an unbound socket can still implicitly bind an ephemeral port | not scoped | not scoped | unrestricted; `linux_unix_sockets` is ignored without validation | unrestricted |
//! | v6-v8 | same as v4-v5 | host-created sockets denied; same-domain sockets work | sending outside the sandbox domain denied | unrestricted; `linux_unix_sockets` is ignored without validation | unrestricted |
//! | v9 | same as v4-v5 | same as v6-v8 | same as v6-v8 | denied by default; `linux_unix_sockets` grants an existing socket path or hierarchy; same-domain sockets work | unrestricted |
//! | v10+ | same as v4-v5 | same as v6-v8 | same as v6-v8 | same as v9 | fixed local ports denied; explicit port 0 and kernel-selected ephemeral binding allowed |
//!
//! On ABI v9+, pathname grants use `LANDLOCK_ACCESS_FS_RESOLVE_UNIX` and
//! cover `connect(2)` plus messages sent with an explicit pathname recipient.
//! They are independent of [`guardrail_core::FsAccess`]: read or write access
//! to a socket's filesystem path does not allow connecting, and a socket grant
//! does not grant file access. Grant paths must exist when the child is
//! spawned. A trusted service reached through a granted socket may pass file
//! descriptors with `SCM_RIGHTS`; those descriptors carry their already-open
//! access independently of `FsAccess`. Granting a socket therefore trusts the
//! service and the capabilities it may send. The raw stable ABI v9 UAPI is
//! used because this crate's `landlock` dependency currently models through
//! ABI v7. The network layer likewise uses ABI v10's stable raw
//! `LANDLOCK_ACCESS_NET_BIND_UDP` and network-port rule layout.
//!
//! Unix-socket creation and `socketpair` are available. Same-domain pathname
//! and abstract sockets work; reaching host-created sockets follows the ABI
//! matrix and explicit grants above. SysV IPC and POSIX message queues are
//! available inside the mandatory fresh IPC namespace described earlier.
//!
//! # OutboundOnly residual TCP listener
//!
//! `NetworkPolicy::OutboundOnly` uses a second Landlock ruleset handling
//! `BindTcp` with no TCP port rules. On ABI v4+, every explicit TCP `bind(2)`
//! therefore fails with `EACCES`, while outbound `connect(2)` and Unix-domain
//! `bind`/`listen` remain untouched. `listen(2)` on an unbound TCP socket is
//! intentionally preserved as an ephemeral-listener residual: the kernel
//! implicitly selects a local port without passing through explicit
//! `bind(2)`, so Landlock does not deny it. This behavior is independent of
//! local IPC.
//!
//! Creating a socket of a family outside the network policy's allowlist
//! fails with `EAFNOSUPPORT`, the errno of a kernel built without that
//! family, so probing runtimes fall back instead of dying: glibc's
//! `getaddrinfo` opens an `AF_NETLINK` route socket to enumerate local
//! addresses on every lookup, and a trapping denial would kill any DNS
//! caller under `Deny` and `OutboundOnly`.
//!
//! Unless the network policy is `Full`, the `io_uring_*` syscalls fail with
//! `ENOSYS`: ring-submitted operations
//! (`IORING_OP_SOCKET`, `IORING_OP_CONNECT`, `IORING_OP_BIND`, ...) are not
//! syscalls, so an open ring would bypass the socket rules. Runtimes that
//! probe io_uring for file I/O see a kernel without io_uring and fall back to
//! plain syscalls.
//!
//! # Process inspection
//!
//! `ptrace(2)`, `process_vm_readv(2)`, and `process_vm_writev(2)` remain
//! available inside the sandbox domain. Landlock implicitly applies its
//! domain hierarchy to ptrace access checks on every ABI supported here: a
//! tracer can inspect a process in the same or a nested domain, but cannot
//! inspect a host process in its parent domain. This is separate from the ABI
//! v6 signal scope in the table above.
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
mod ipc;
mod net;
mod ns;
mod rlimit;
mod seccomp;
mod support;

pub use backend::LinuxBackend;
