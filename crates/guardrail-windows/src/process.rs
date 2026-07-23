//! Suspended Windows process launch under a Job Object, with isolated handle
//! inheritance through an inert helper process.

#![cfg(windows)]

use std::any::Any;
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, OwnedHandle, RawHandle};
use std::path::Path;
use std::process::{ChildStderr, ChildStdin, ChildStdout};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::{io, mem, ptr};

use guardrail_core::{
    Error, NetworkPolicy, Result, SandboxChild, SandboxCommand, StdioMode, WindowsChildStdio,
};
use windows_sys::Win32::Foundation::{
    DUPLICATE_CLOSE_SOURCE, DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_ACCESS_DENIED,
    GENERIC_READ, GENERIC_WRITE, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::{
    CreateRestrictedToken, GetTokenInformation, SECURITY_CAPABILITIES, SID_AND_ATTRIBUTES,
    TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_GROUPS, TOKEN_QUERY, TOKEN_USER, TokenGroups,
    TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, FILE_READ_ATTRIBUTES,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TYPE_CHAR, GetFileAttributesW, GetFileType,
    INVALID_FILE_ATTRIBUTES, OPEN_EXISTING, PIPE_ACCESS_INBOUND, PIPE_ACCESS_OUTBOUND,
};
use windows_sys::Win32::System::Console::{
    GetConsoleMode, GetStdHandle, STD_ERROR_HANDLE, STD_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows_sys::Win32::System::JobObjects::{AssignProcessToJobObject, TerminateJobObject};
use windows_sys::Win32::System::Pipes::{
    CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW, CreateProcessW,
    DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess,
    GetCurrentProcessId, InitializeProcThreadAttributeList, OpenProcessToken,
    PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
    PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
    PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOEXW, STARTUPINFOW, TerminateProcess,
    UpdateProcThreadAttribute,
};
use windows_sys::Win32::System::WindowsProgramming::PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;

use crate::cache::{CachedAppContainer, raw_security_capabilities};
use crate::handle::{bool_result, owned_handle_from_raw, resume_then_close_thread};
use crate::job;

const SE_GROUP_INTEGRITY: u32 = 0x20;

pub(crate) fn launch(
    command: SandboxCommand,
    env: &BTreeMap<String, String>,
    job: OwnedHandle,
    appcontainer: Arc<CachedAppContainer>,
    network: NetworkPolicy,
) -> Result<SandboxChild> {
    let mut command_line = command_line_block(&command.program, &command.args);
    let environment = environment_block(env);
    let application_name = application_name(&command.program, env)?;
    let application_name_ptr = application_name.as_ptr();
    let cwd = command
        .current_dir
        .as_ref()
        .map(|path| wide_null(path.as_os_str()));
    let cwd_ptr = cwd.as_ref().map_or(ptr::null(), |wide| wide.as_ptr());

    let stdio =
        prepare_stdio(command.stdin, command.stdout, command.stderr).map_err(Error::Spawn)?;
    // PROC_THREAD_ATTRIBUTE_HANDLE_LIST requires inheritable handles. Keep
    // duplicable copies in an inert helper process rather than this
    // multithreaded host, so unrelated concurrent CreateProcess calls cannot
    // receive file, pipe, or device handles. Real consoles take the
    // creation-time inheritance path described by HandleBroker::new.
    let mut owned_broker = None;
    let broker: &HandleBroker = if stdio.has_console_handle() {
        owned_broker.insert(
            HandleBroker::new(Some(&stdio))
                .map_err(|err| Error::confinement("handle broker", err))?,
        )
    } else {
        handle_broker().map_err(|err| Error::confinement("handle broker", err))?
    };
    let brokered_stdio =
        BrokeredStdio::new(broker, &stdio).map_err(|err| Error::confinement("stdio", err))?;

    let mut startup = STARTUPINFOEXW {
        StartupInfo: windows_sys::Win32::System::Threading::STARTUPINFOW {
            cb: mem::size_of::<STARTUPINFOEXW>() as u32,
            dwFlags: STARTF_USESTDHANDLES,
            hStdInput: brokered_stdio.stdin.raw,
            hStdOutput: brokered_stdio.stdout.raw,
            hStdError: brokered_stdio.stderr.raw,
            ..windows_sys::Win32::System::Threading::STARTUPINFOW::default()
        },
        ..STARTUPINFOEXW::default()
    };
    // UpdateProcThreadAttribute retains these pointers until the attribute list
    // is destroyed, so every pointee must be declared before the list.
    let mut security_capabilities = appcontainer.security_capabilities(network)?;
    let mut all_application_packages_policy =
        Box::new(PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT);
    let mut inheritable_handles: [HANDLE; 3] = [
        brokered_stdio.stdin.raw,
        brokered_stdio.stdout.raw,
        brokered_stdio.stderr.raw,
    ];
    let mut parent_process = broker.process.as_raw_handle();
    let mut attributes =
        AttributeList::new(4).map_err(|err| Error::confinement("appcontainer", err))?;
    attributes
        .update_security_capabilities(raw_security_capabilities(&mut security_capabilities))
        .map_err(|err| Error::confinement("appcontainer", err))?;
    attributes
        .opt_out_all_application_packages(all_application_packages_policy.as_mut())
        .map_err(|err| Error::confinement("appcontainer", err))?;
    // Restrict inheritance to exactly the three standard handles so no other
    // transiently-inheritable parent handle can leak into the sandbox even
    // though bInheritHandles must be TRUE for stdio to cross.
    attributes
        .update_handle_list(&mut inheritable_handles)
        .map_err(|err| Error::confinement("handle hygiene", err))?;
    attributes
        .update_parent_process(&mut parent_process)
        .map_err(|err| Error::confinement("handle broker", err))?;
    startup.lpAttributeList = attributes.as_mut_ptr();
    let restricted_token =
        restricted_token(appcontainer.restricting_sid(), appcontainer.reallow_sid())
            .map_err(|err| Error::confinement("restricted-token", err))?;

    let mut process_info = PROCESS_INFORMATION::default();

    // SAFETY: all pointers either are null or point to nul-terminated UTF-16
    // buffers that outlive the call. `command_line` is mutable because
    // CreateProcessAsUserW may rewrite its command-line buffer. The restricted
    // token, extended startup attribute list, SECURITY_CAPABILITIES, helper
    // process, and three helper-owned standard handles outlive the call.
    let created = unsafe {
        CreateProcessAsUserW(
            restricted_token.as_raw_handle(),
            application_name_ptr,
            command_line.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            1,
            CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
            environment.as_ptr().cast(),
            cwd_ptr,
            &startup.StartupInfo,
            &mut process_info,
        )
    };
    let create_result = bool_result(created).map_err(Error::Spawn);
    // The target has inherited its own copies on success. On failure these
    // were never consumed. Either way, remove the transient broker copies now.
    drop(brokered_stdio);
    create_result?;

    // The child holds its own inherited copies now, so close our local source
    // handles before the remaining confinement steps.
    let PreparedStdio {
        child_stdin,
        child_stdout,
        child_stderr,
        parent: parent_stdio,
    } = stdio;
    drop((child_stdin, child_stdout, child_stderr));

    // SAFETY: on success both PROCESS_INFORMATION handles are valid and owned
    // by this process; ownership transfers to the OwnedHandles here.
    let process = unsafe { owned_handle_from_raw(process_info.hProcess) }.map_err(Error::Spawn)?;
    // SAFETY: as above for the primary thread handle.
    let thread = match unsafe { owned_handle_from_raw(process_info.hThread) } {
        Ok(thread) => thread,
        Err(err) => {
            terminate_process(&process);
            return Err(Error::Spawn(err));
        }
    };

    // SAFETY: `job` is a live Job Object handle and `process` is the suspended
    // process handle returned by CreateProcessW. The call borrows both handles.
    let assigned =
        unsafe { AssignProcessToJobObject(job.as_raw_handle(), process.as_raw_handle()) };
    if let Err(err) = bool_result(assigned) {
        terminate_process(&process);
        return Err(Error::confinement("job", err));
    }

    if let Err(err) = resume_then_close_thread(thread) {
        terminate_job(&job);
        return Err(Error::Spawn(err));
    }

    let pid = process_info.dwProcessId;
    let mut guards: Vec<Box<dyn Any + Send>> = vec![Box::new(appcontainer)];
    if let Some(broker) = owned_broker {
        // A target inheriting a real console handle must keep its
        // launch-specific broker (and the broker's outer Job Object) alive.
        guards.push(Box::new(broker));
    }
    // SAFETY: the owned process handle, owned job handle, and pid all come
    // from the successful CreateProcessW + AssignProcessToJobObject sequence
    // above and are transferred into SandboxChild together with the parent
    // pipe ends. The cleanup guards own AppContainer/ACL cleanup state and,
    // when required, the launch-specific handle broker; all are dropped after
    // the raw child and Job Object handles.
    Ok(unsafe {
        SandboxChild::from_windows_handles_with_guards(process, job, pid, parent_stdio, guards)
    })
}

/// An inert process whose handle table is the source for explicit inheritance.
///
/// Windows requires every handle in PROC_THREAD_ATTRIBUTE_HANDLE_LIST to be
/// inheritable. Keeping duplicable temporary handles here, rather than in the
/// host, prevents unrelated host process launches from inheriting them. The
/// helper never executes user code: its primary thread stays suspended, and
/// its Job Object terminates it when the owner closes the job handle.
struct HandleBroker {
    // Drop the job first so it terminates the suspended process before the
    // process handle itself closes.
    _job: OwnedHandle,
    process: OwnedHandle,
    // Raw handle values are process-local scalars. Store them as integers so
    // the broker itself remains Send + Sync; they are converted back only for
    // Win32 calls that name handles in the broker's table.
    console_stdio: [usize; 3],
}

impl HandleBroker {
    fn new(stdio: Option<&PreparedStdio>) -> io::Result<Self> {
        let job = job::create_kill_on_close()?;
        let console_copies = ConsoleCopies::new(stdio)?;
        let console_stdio = console_copies.remote_values();
        let mut inherited_console_handles = console_copies.raw_handles();
        let executable = std::env::current_exe()?;
        let application = wide_null(executable.as_os_str());
        let mut command_line = quote_arg(executable.as_os_str());
        command_line.push(0);
        let mut startup = STARTUPINFOEXW {
            StartupInfo: STARTUPINFOW {
                cb: mem::size_of::<STARTUPINFOW>() as u32,
                ..STARTUPINFOW::default()
            },
            ..STARTUPINFOEXW::default()
        };
        let mut creation_flags = CREATE_SUSPENDED;
        let mut inherit_handles = 0;
        let mut attributes = if inherited_console_handles.is_empty() {
            None
        } else {
            Some(AttributeList::new(1)?)
        };

        if let Some(attributes) = attributes.as_mut() {
            // Unlike files and pipes, Windows console handles cannot be
            // duplicated for use by another process. Share them with this
            // launch-specific broker during its creation instead. The list
            // still restricts what the broker receives to those console
            // handles, and inherited handles keep the same numeric values.
            attributes.update_handle_list(&mut inherited_console_handles)?;
            startup.StartupInfo.cb = mem::size_of::<STARTUPINFOEXW>() as u32;
            startup.lpAttributeList = attributes.as_mut_ptr();
            creation_flags |= EXTENDED_STARTUPINFO_PRESENT;
            inherit_handles = 1;
        }
        let mut process_info = PROCESS_INFORMATION::default();

        // SAFETY: application and command_line are nul-terminated buffers
        // that outlive this call. If present, the extended attribute list and
        // its console handles also outlive the call. All other optional
        // pointers are null, and process_info is a valid out-pointer.
        let created = unsafe {
            CreateProcessW(
                application.as_ptr(),
                command_line.as_mut_ptr(),
                ptr::null(),
                ptr::null(),
                inherit_handles,
                creation_flags,
                ptr::null(),
                ptr::null(),
                &startup.StartupInfo,
                &mut process_info,
            )
        };
        bool_result(created)?;

        // SAFETY: successful CreateProcessW returns two unique owned handles.
        let process = unsafe { owned_handle_from_raw(process_info.hProcess) }?;
        // SAFETY: as above for the primary thread handle.
        let thread = match unsafe { owned_handle_from_raw(process_info.hThread) } {
            Ok(thread) => thread,
            Err(err) => {
                terminate_process(&process);
                return Err(err);
            }
        };

        // SAFETY: both handles are live and owned by this process. The helper
        // is still suspended, so it cannot create descendants before joining
        // the process-lifetime cleanup job.
        let assigned =
            unsafe { AssignProcessToJobObject(job.as_raw_handle(), process.as_raw_handle()) };
        if let Err(err) = bool_result(assigned) {
            terminate_process(&process);
            return Err(err);
        }

        // Closing the primary thread handle does not resume it. The process
        // remains inert until the job terminates it.
        drop(thread);
        Ok(Self {
            _job: job,
            process,
            console_stdio,
        })
    }

    fn inherit_stream(
        &self,
        source: RawHandle,
        stream_index: usize,
    ) -> io::Result<RemoteHandle<'_>> {
        if is_console_handle(source) {
            let raw = *self.console_stdio.get(stream_index).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "invalid standard stream index")
            })? as HANDLE;
            if raw.is_null() {
                return Err(io::Error::other(
                    "console handle was not shared with the launch-specific broker",
                ));
            }
            return Ok(RemoteHandle { broker: self, raw });
        }

        self.duplicate_inheritable(source)
    }

    fn duplicate_inheritable(&self, source: RawHandle) -> io::Result<RemoteHandle<'_>> {
        // SAFETY: GetCurrentProcess returns a process pseudo-handle and cannot
        // fail. The broker process handle has PROCESS_DUP_HANDLE access because
        // it came directly from CreateProcessW.
        let current_process = unsafe { GetCurrentProcess() };
        let mut duplicated = ptr::null_mut();
        // SAFETY: source is live for this call, process handles are valid, and
        // duplicated is a valid out-pointer. The returned scalar is a handle
        // value in the broker's handle table, not in this process.
        let ok = unsafe {
            DuplicateHandle(
                current_process,
                source,
                self.process.as_raw_handle(),
                &mut duplicated,
                0,
                1,
                DUPLICATE_SAME_ACCESS,
            )
        };
        bool_result(ok)?;
        Ok(RemoteHandle {
            broker: self,
            raw: duplicated,
        })
    }
}

fn handle_broker() -> io::Result<&'static HandleBroker> {
    static BROKER: OnceLock<HandleBroker> = OnceLock::new();

    if let Some(broker) = BROKER.get() {
        return Ok(broker);
    }

    let candidate = HandleBroker::new(None)?;
    if let Err(unused) = BROKER.set(candidate) {
        // Another thread won initialization. Dropping this candidate closes
        // its job, which terminates its suspended helper process.
        drop(unused);
    }
    BROKER
        .get()
        .ok_or_else(|| io::Error::other("handle broker initialization did not persist"))
}

/// A handle value owned by the broker process.
struct RemoteHandle<'a> {
    broker: &'a HandleBroker,
    raw: HANDLE,
}

impl Drop for RemoteHandle<'_> {
    fn drop(&mut self) {
        // SAFETY: raw is a live handle in broker.process. With
        // DUPLICATE_CLOSE_SOURCE, a null target process closes that remote
        // source without creating a local duplicate; Microsoft specifies that
        // the source is closed even if DuplicateHandle reports an error.
        let _closed = unsafe {
            DuplicateHandle(
                self.broker.process.as_raw_handle(),
                self.raw,
                ptr::null_mut(),
                ptr::null_mut(),
                0,
                0,
                DUPLICATE_CLOSE_SOURCE,
            )
        };
    }
}

/// The broker-owned copies passed through the explicit inheritance list.
struct BrokeredStdio<'a> {
    stdin: RemoteHandle<'a>,
    stdout: RemoteHandle<'a>,
    stderr: RemoteHandle<'a>,
}

impl<'a> BrokeredStdio<'a> {
    fn new(broker: &'a HandleBroker, stdio: &PreparedStdio) -> io::Result<Self> {
        let stdin = broker.inherit_stream(stdio.child_stdin.as_raw_handle(), 0)?;
        let stdout = broker.inherit_stream(stdio.child_stdout.as_raw_handle(), 1)?;
        let stderr = broker.inherit_stream(stdio.child_stderr.as_raw_handle(), 2)?;
        Ok(Self {
            stdin,
            stdout,
            stderr,
        })
    }
}

/// Inheritable host-local console copies used only while creating a
/// launch-specific broker. Console handles are the one Windows handle class
/// that cannot be duplicated directly into an already-running broker.
struct ConsoleCopies {
    handles: [Option<OwnedHandle>; 3],
}

impl ConsoleCopies {
    fn new(stdio: Option<&PreparedStdio>) -> io::Result<Self> {
        let mut handles = [None, None, None];
        let Some(stdio) = stdio else {
            return Ok(Self { handles });
        };

        for (slot, source) in [&stdio.child_stdin, &stdio.child_stdout, &stdio.child_stderr]
            .into_iter()
            .enumerate()
        {
            if is_console_handle(source.as_raw_handle()) {
                let destination = handles.get_mut(slot).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "invalid standard stream index")
                })?;
                *destination = Some(duplicate_local_with_inheritability(
                    source.as_raw_handle(),
                    true,
                )?);
            }
        }

        Ok(Self { handles })
    }

    fn raw_handles(&self) -> Vec<HANDLE> {
        self.handles
            .iter()
            .filter_map(|handle| handle.as_ref().map(AsRawHandle::as_raw_handle))
            .collect()
    }

    fn remote_values(&self) -> [usize; 3] {
        std::array::from_fn(|slot| {
            self.handles
                .get(slot)
                .and_then(Option::as_ref)
                .map_or(0, |handle| handle.as_raw_handle() as usize)
        })
    }
}

/// Which way a standard stream flows, from the child's perspective.
#[derive(Clone, Copy)]
enum StreamDirection {
    /// The child reads this stream (stdin).
    Read,
    /// The child writes this stream (stdout, stderr).
    Write,
}

/// The three non-inheritable local stream sources plus the parent's retained
/// pipe ends.
struct PreparedStdio {
    child_stdin: OwnedHandle,
    child_stdout: OwnedHandle,
    child_stderr: OwnedHandle,
    parent: WindowsChildStdio,
}

impl PreparedStdio {
    fn has_console_handle(&self) -> bool {
        [&self.child_stdin, &self.child_stdout, &self.child_stderr]
            .into_iter()
            .any(|handle| is_console_handle(handle.as_raw_handle()))
    }
}

/// Resolve the command's stdio modes into concrete local handles (issue #21):
/// every mode yields a valid non-inheritable source for the handle broker, and
/// `Piped` additionally retains our overlapped end for the caller.
fn prepare_stdio(
    stdin: StdioMode,
    stdout: StdioMode,
    stderr: StdioMode,
) -> io::Result<PreparedStdio> {
    let (child_stdin, ours_stdin) = child_stream(stdin, STD_INPUT_HANDLE, StreamDirection::Read)?;
    let (child_stdout, ours_stdout) =
        child_stream(stdout, STD_OUTPUT_HANDLE, StreamDirection::Write)?;
    let (child_stderr, ours_stderr) =
        child_stream(stderr, STD_ERROR_HANDLE, StreamDirection::Write)?;
    Ok(PreparedStdio {
        child_stdin,
        child_stdout,
        child_stderr,
        // The pipe ends are overlapped handles, as these From impls require.
        parent: WindowsChildStdio {
            stdin: ours_stdin.map(ChildStdin::from),
            stdout: ours_stdout.map(ChildStdout::from),
            stderr: ours_stderr.map(ChildStderr::from),
        },
    })
}

/// Produce the local source handle for one stream, plus our retained overlapped
/// pipe end when the mode is [`StdioMode::Piped`].
fn child_stream(
    mode: StdioMode,
    stdio_id: STD_HANDLE,
    direction: StreamDirection,
) -> io::Result<(OwnedHandle, Option<OwnedHandle>)> {
    match mode {
        StdioMode::Inherit => {
            // SAFETY: GetStdHandle takes a scalar id; the returned handle is
            // borrowed from the process std slots, never closed here.
            let current = unsafe { GetStdHandle(stdio_id) };
            if current.is_null() || current == INVALID_HANDLE_VALUE {
                // A detached parent (e.g. a GUI process) has no stream to
                // share; hand the child the null device rather than an
                // invalid handle.
                Ok((open_null(direction)?, None))
            } else {
                Ok((duplicate_local(current)?, None))
            }
        }
        StdioMode::Null => Ok((open_null(direction)?, None)),
        StdioMode::Piped => {
            let ours_readable = matches!(direction, StreamDirection::Write);
            let (ours, theirs) = anon_pipe(ours_readable)?;
            Ok((theirs, Some(ours)))
        }
        StdioMode::File(file) => Ok((duplicate_local(file.as_raw_handle())?, None)),
    }
}

/// Duplicate `source` within this process without making the copy inheritable.
/// The broker creates the inheritable copy in its isolated handle table later.
fn duplicate_local(source: RawHandle) -> io::Result<OwnedHandle> {
    duplicate_local_with_inheritability(source, false)
}

fn duplicate_local_with_inheritability(
    source: RawHandle,
    inheritable: bool,
) -> io::Result<OwnedHandle> {
    // SAFETY: GetCurrentProcess returns the process pseudo-handle and cannot
    // fail; the pseudo-handle needs no closing.
    let current_process = unsafe { GetCurrentProcess() };
    let mut duplicated = ptr::null_mut();
    // SAFETY: `source` is a live handle for the duration of this call and
    // `duplicated` is a valid out-pointer.
    let ok = unsafe {
        DuplicateHandle(
            current_process,
            source,
            current_process,
            &mut duplicated,
            0,
            i32::from(inheritable),
            DUPLICATE_SAME_ACCESS,
        )
    };
    bool_result(ok)?;
    // SAFETY: on success the duplicate is a valid handle uniquely owned by us.
    unsafe { owned_handle_from_raw(duplicated) }
}

fn is_console_handle(handle: RawHandle) -> bool {
    let mut mode = 0;
    // SAFETY: handle is borrowed and live for this call; mode is a valid
    // out-pointer. GetConsoleMode requires GENERIC_READ, so a write-only
    // character handle that fails with access denied is conservatively sent
    // through the creation-time inheritance path too.
    if unsafe { GetConsoleMode(handle, &mut mode) } != 0 {
        return true;
    }
    // SAFETY: GetLastError reads the calling thread's error state immediately
    // after the failed GetConsoleMode call.
    if unsafe { GetLastError() } != ERROR_ACCESS_DENIED {
        return false;
    }
    // SAFETY: handle remains borrowed and live for this type query.
    unsafe { GetFileType(handle) == FILE_TYPE_CHAR }
}

/// Open a non-inheritable handle to the null device, readable for stdin slots
/// and writable for stdout/stderr slots.
fn open_null(direction: StreamDirection) -> io::Result<OwnedHandle> {
    let path = wide_null(OsStr::new(r"\\.\NUL"));
    let access = match direction {
        StreamDirection::Read => GENERIC_READ,
        StreamDirection::Write => GENERIC_WRITE,
    };
    // SAFETY: the path is a nul-terminated UTF-16 buffer; null security
    // attributes make the returned handle non-inheritable.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            ptr::null(),
            OPEN_EXISTING,
            0,
            ptr::null_mut(),
        )
    };
    // SAFETY: CreateFileW returns a uniquely owned handle or
    // INVALID_HANDLE_VALUE, which owned_handle_from_raw rejects.
    unsafe { owned_handle_from_raw(handle) }
}

/// Create a std-style anonymous stdio pipe pair: our end is asynchronous
/// (`FILE_FLAG_OVERLAPPED`, as the `ChildStdin`/`ChildStdout`/`ChildStderr`
/// conversions require), the child's end is synchronous and non-inheritable in
/// this process. The broker creates its inheritable copy before launch.
fn anon_pipe(ours_readable: bool) -> io::Result<(OwnedHandle, OwnedHandle)> {
    // The capacity std uses; a typical Linux pipe default.
    const PIPE_BUFFER_CAPACITY: u32 = 64 * 1024;
    static PIPE_COUNTER: AtomicU64 = AtomicU64::new(0);

    // SAFETY: GetCurrentProcessId reads process state and cannot fail.
    let pid = unsafe { GetCurrentProcessId() };
    let mut tries = 0;
    loop {
        tries += 1;
        let name = format!(
            r"\\.\pipe\guardrail.{pid}.{}",
            PIPE_COUNTER.fetch_add(1, Ordering::Relaxed),
        );
        let wide_name = wide_null(OsStr::new(&name));

        let direction = if ours_readable {
            PIPE_ACCESS_INBOUND
        } else {
            PIPE_ACCESS_OUTBOUND
        };
        // SAFETY: the name is a nul-terminated UTF-16 buffer outliving the
        // call; the returned handle is checked and owned below.
        let raw_ours = unsafe {
            CreateNamedPipeW(
                wide_name.as_ptr(),
                direction | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                PIPE_BUFFER_CAPACITY,
                PIPE_BUFFER_CAPACITY,
                0,
                ptr::null(),
            )
        };
        // SAFETY: as above; null/INVALID_HANDLE_VALUE are rejected with the
        // OS error preserved.
        let ours = match unsafe { owned_handle_from_raw(raw_ours) } {
            Ok(handle) => handle,
            Err(err) => {
                // FILE_FLAG_FIRST_PIPE_INSTANCE turns a name collision (e.g.
                // a squatted name) into ERROR_ACCESS_DENIED; retry under a
                // fresh name.
                if err.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) && tries < 10 {
                    continue;
                }
                return Err(err);
            }
        };

        let access = if ours_readable {
            // FILE_READ_ATTRIBUTES lets the child answer attribute queries on
            // its stdout/stderr (GetFileInformationByHandle and friends), as
            // std grants on its own child pipe ends.
            GENERIC_WRITE | FILE_READ_ATTRIBUTES
        } else {
            GENERIC_READ
        };
        // SAFETY: name outlives the call; our unconnected single-instance
        // server end guarantees this opens our pipe. Null security attributes
        // make the handle non-inheritable, and omitting FILE_FLAG_OVERLAPPED
        // keeps it synchronous.
        let raw_theirs = unsafe {
            CreateFileW(
                wide_name.as_ptr(),
                access,
                0,
                ptr::null(),
                OPEN_EXISTING,
                0,
                ptr::null_mut(),
            )
        };
        // SAFETY: as above.
        let theirs = unsafe { owned_handle_from_raw(raw_theirs) }?;
        return Ok((ours, theirs));
    }
}

fn restricted_token(
    filesystem_sid: windows_sys::Win32::Security::PSID,
    reallow_sid: windows_sys::Win32::Security::PSID,
) -> io::Result<OwnedHandle> {
    let mut current_token = ptr::null_mut();
    let opened = unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY,
            &mut current_token,
        )
    };
    bool_result(opened)?;
    let current_token = unsafe { owned_handle_from_raw(current_token) }?;

    let mut user_bytes = 0;
    unsafe {
        GetTokenInformation(
            current_token.as_raw_handle(),
            TokenUser,
            ptr::null_mut(),
            0,
            &mut user_bytes,
        );
    }
    if user_bytes == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut user_storage = vec![0usize; (user_bytes as usize).div_ceil(mem::size_of::<usize>())];
    let queried = unsafe {
        GetTokenInformation(
            current_token.as_raw_handle(),
            TokenUser,
            user_storage.as_mut_ptr().cast(),
            user_bytes,
            &mut user_bytes,
        )
    };
    bool_result(queried)?;
    let user_sid = unsafe { (*user_storage.as_ptr().cast::<TOKEN_USER>()).User.Sid };

    let mut group_bytes = 0;
    unsafe {
        GetTokenInformation(
            current_token.as_raw_handle(),
            TokenGroups,
            ptr::null_mut(),
            0,
            &mut group_bytes,
        );
    }
    if group_bytes == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut group_storage = vec![0usize; (group_bytes as usize).div_ceil(mem::size_of::<usize>())];
    let queried = unsafe {
        GetTokenInformation(
            current_token.as_raw_handle(),
            TokenGroups,
            group_storage.as_mut_ptr().cast(),
            group_bytes,
            &mut group_bytes,
        )
    };
    bool_result(queried)?;
    let groups = unsafe { &*group_storage.as_ptr().cast::<TOKEN_GROUPS>() };
    let groups =
        unsafe { std::slice::from_raw_parts(groups.Groups.as_ptr(), groups.GroupCount as usize) };

    // Mirroring Chromium's USER_RESTRICTED_SAME_ACCESS level, copying the
    // source token's user and non-integrity group SIDs lets normal runtime
    // resources pass the second check. The extra guardrail SIDs add only a
    // deny-ACE veto and its explicit re-allow exception; neither can broaden
    // access because both checks must pass.
    let mut restricting_sids = Vec::with_capacity(groups.len() + 3);
    restricting_sids.push(SID_AND_ATTRIBUTES {
        Sid: user_sid,
        Attributes: 0,
    });
    restricting_sids.extend(
        groups
            .iter()
            .filter(|group| group.Attributes & SE_GROUP_INTEGRITY == 0)
            .map(|group| SID_AND_ATTRIBUTES {
                Sid: group.Sid,
                Attributes: 0,
            }),
    );
    restricting_sids.push(SID_AND_ATTRIBUTES {
        Sid: filesystem_sid,
        Attributes: 0,
    });
    restricting_sids.push(SID_AND_ATTRIBUTES {
        Sid: reallow_sid,
        Attributes: 0,
    });
    let mut token = ptr::null_mut();
    let created = unsafe {
        CreateRestrictedToken(
            current_token.as_raw_handle(),
            0,
            0,
            ptr::null(),
            0,
            ptr::null(),
            restricting_sids.len() as u32,
            restricting_sids.as_ptr(),
            &mut token,
        )
    };
    bool_result(created)?;
    unsafe { owned_handle_from_raw(token) }
}

struct AttributeList {
    storage: Vec<usize>,
}

impl AttributeList {
    fn new(attribute_count: u32) -> io::Result<Self> {
        let mut bytes = 0usize;
        unsafe {
            InitializeProcThreadAttributeList(ptr::null_mut(), attribute_count, 0, &mut bytes);
        }
        if bytes == 0 {
            return Err(io::Error::last_os_error());
        }

        let words = bytes.div_ceil(mem::size_of::<usize>());
        let mut list = Self {
            storage: vec![0usize; words],
        };
        let ok = unsafe {
            InitializeProcThreadAttributeList(list.as_mut_ptr(), attribute_count, 0, &mut bytes)
        };
        bool_result(ok)?;
        Ok(list)
    }

    fn as_mut_ptr(
        &mut self,
    ) -> windows_sys::Win32::System::Threading::LPPROC_THREAD_ATTRIBUTE_LIST {
        self.storage.as_mut_ptr().cast()
    }

    fn update_security_capabilities(
        &mut self,
        security_capabilities: *mut SECURITY_CAPABILITIES,
    ) -> io::Result<()> {
        let ok = unsafe {
            UpdateProcThreadAttribute(
                self.as_mut_ptr(),
                0,
                PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
                security_capabilities.cast(),
                mem::size_of::<SECURITY_CAPABILITIES>(),
                ptr::null_mut(),
                ptr::null(),
            )
        };
        bool_result(ok)
    }

    fn opt_out_all_application_packages(&mut self, policy: &mut u32) -> io::Result<()> {
        let ok = unsafe {
            UpdateProcThreadAttribute(
                self.as_mut_ptr(),
                0,
                PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY as usize,
                ptr::from_mut(policy).cast(),
                mem::size_of::<u32>(),
                ptr::null_mut(),
                ptr::null(),
            )
        };
        bool_result(ok)
    }

    /// Restrict handle inheritance to exactly `handles`. The array must stay
    /// alive (and its handles open) until process creation has completed,
    /// because the attribute retains the pointer.
    fn update_handle_list(&mut self, handles: &mut [HANDLE]) -> io::Result<()> {
        // SAFETY: `handles` points to live handle values and, per this method's
        // contract, outlives the attribute list that retains the pointer; all
        // other arguments are scalars or null.
        let ok = unsafe {
            UpdateProcThreadAttribute(
                self.as_mut_ptr(),
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                handles.as_mut_ptr().cast(),
                mem::size_of_val(handles),
                ptr::null_mut(),
                ptr::null(),
            )
        };
        bool_result(ok)
    }

    /// Select the inert broker as the source process for handle inheritance.
    fn update_parent_process(&mut self, process: &mut HANDLE) -> io::Result<()> {
        // SAFETY: process points to a live process handle with
        // PROCESS_CREATE_PROCESS access and outlives the attribute list; all
        // remaining arguments are scalars or reserved null pointers.
        let ok = unsafe {
            UpdateProcThreadAttribute(
                self.as_mut_ptr(),
                0,
                PROC_THREAD_ATTRIBUTE_PARENT_PROCESS as usize,
                ptr::from_mut(process).cast(),
                mem::size_of::<HANDLE>(),
                ptr::null_mut(),
                ptr::null(),
            )
        };
        bool_result(ok)
    }
}

impl Drop for AttributeList {
    fn drop(&mut self) {
        unsafe {
            DeleteProcThreadAttributeList(self.as_mut_ptr());
        }
    }
}

fn terminate_process(process: &OwnedHandle) {
    // SAFETY: best-effort cleanup for a process handle we own. The process is
    // still suspended on assignment/setup failures, so ignoring cleanup errors
    // is preferable to masking the original failure.
    let _ = unsafe { TerminateProcess(process.as_raw_handle(), 1) };
}

fn terminate_job(job: &OwnedHandle) {
    // SAFETY: best-effort cleanup for a Job Object handle we own. The process
    // has already been assigned to this job if this path is reached.
    let _ = unsafe { TerminateJobObject(job.as_raw_handle(), 1) };
}

fn command_line_block(program: &OsStr, args: &[OsString]) -> Vec<u16> {
    let mut out = quote_arg(program);
    for arg in args {
        out.push(b' ' as u16);
        out.extend(quote_arg(arg));
    }
    out.push(0);
    out
}

/// Compute `lpApplicationName` for `CreateProcessAsUserW`.
///
/// A program containing a path separator is passed through as given. A bare
/// name is resolved against the `PATH` of the sandbox
/// environment — the only environment the child will see — so the launched
/// binary is determined by the sandbox configuration alone (issue #23). Each
/// absolute `PATH` directory is probed with the `std::process::Command` rules:
/// empty entries are skipped, `.exe` is appended when the name has no
/// extension, and existence is checked with `GetFileAttributesW`. Relative
/// entries are rejected because Windows would resolve them against the
/// supervisor's current-directory state. The supervisor's own `PATH`, its
/// executable's directory, the system directories, and every current
/// directory are never consulted; a bare name with no match is a `NotFound`
/// spawn error rather than a second, parent-dependent lookup by
/// `CreateProcessW` itself.
fn application_name(program: &OsStr, env: &BTreeMap<String, String>) -> Result<Vec<u16>> {
    if has_path_separator(program) {
        return Ok(wide_null(program));
    }

    let sandbox_path = env
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("PATH"))
        .map(|(_, value)| value.as_str())
        .unwrap_or_default();
    let mut sandbox_dirs = Vec::new();
    for dir in std::env::split_paths(sandbox_path) {
        if dir.as_os_str().is_empty() {
            continue;
        }
        if !dir.is_absolute() {
            return Err(Error::Spawn(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("sandbox PATH entry {dir:?} is not absolute"),
            )));
        }
        sandbox_dirs.push(dir);
    }
    // CreateProcessW's search appends `.exe` only to extensionless names;
    // std::process::Command mirrors that rule, and so does this lookup.
    let has_extension = program.as_encoded_bytes().contains(&b'.');
    for dir in sandbox_dirs {
        let mut candidate = dir.join(program);
        if !has_extension {
            candidate.set_extension("exe");
        }
        if program_exists(&candidate) {
            return Ok(wide_null(candidate.as_os_str()));
        }
    }

    Err(Error::Spawn(io::Error::new(
        io::ErrorKind::NotFound,
        format!("program {program:?} not found in the sandbox PATH"),
    )))
}

/// Whether `path` names an existing filesystem entry, without following
/// symlinks — the same `GetFileAttributesW` probe std uses for its lookup.
fn program_exists(path: &Path) -> bool {
    let wide = wide_null(path.as_os_str());
    // SAFETY: the path is a nul-terminated UTF-16 buffer that outlives the
    // call.
    unsafe { GetFileAttributesW(wide.as_ptr()) != INVALID_FILE_ATTRIBUTES }
}

fn has_path_separator(value: &OsStr) -> bool {
    value
        .encode_wide()
        .any(|ch| ch == b'\\' as u16 || ch == b'/' as u16)
}

fn quote_arg(arg: &OsStr) -> Vec<u16> {
    quote_arg_wide(&arg.encode_wide().collect::<Vec<_>>())
}

fn quote_arg_wide(arg: &[u16]) -> Vec<u16> {
    if !arg.is_empty()
        && !arg
            .iter()
            .any(|ch| *ch == b' ' as u16 || *ch == b'\t' as u16 || *ch == b'"' as u16)
    {
        return arg.to_vec();
    }

    let mut out = Vec::with_capacity(arg.len() + 2);
    out.push(b'"' as u16);
    let mut backslashes = 0usize;

    for ch in arg {
        match *ch {
            ch if ch == b'\\' as u16 => backslashes += 1,
            ch if ch == b'"' as u16 => {
                out.extend(std::iter::repeat_n(b'\\' as u16, backslashes * 2 + 1));
                out.push(ch);
                backslashes = 0;
            }
            ch => {
                out.extend(std::iter::repeat_n(b'\\' as u16, backslashes));
                backslashes = 0;
                out.push(ch);
            }
        }
    }

    out.extend(std::iter::repeat_n(b'\\' as u16, backslashes * 2));
    out.push(b'"' as u16);
    out
}

fn environment_block(env: &BTreeMap<String, String>) -> Vec<u16> {
    let mut entries = env.iter().collect::<Vec<_>>();
    entries.sort_by_key(|(key, _)| key.to_ascii_uppercase());

    let mut block = Vec::new();
    for (key, value) in entries {
        block.extend(OsStr::new(key.as_str()).encode_wide());
        block.push(b'=' as u16);
        block.extend(OsStr::new(value.as_str()).encode_wide());
        block.push(0);
    }
    if block.is_empty() {
        block.push(0);
        block.push(0);
        return block;
    }
    block.push(0);
    block
}

fn wide_null(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wide_to_string(wide: &[u16]) -> String {
        String::from_utf16(wide).expect("test data is valid UTF-16")
    }

    #[test]
    fn quotes_empty_args() {
        assert_eq!(wide_to_string(&quote_arg(OsStr::new(""))), "\"\"");
    }

    #[test]
    fn leaves_simple_args_unquoted() {
        assert_eq!(wide_to_string(&quote_arg(OsStr::new("plain"))), "plain");
    }

    #[test]
    fn quotes_spaces_and_embedded_quotes() {
        assert_eq!(
            wide_to_string(&quote_arg(OsStr::new("two words"))),
            "\"two words\""
        );
        assert_eq!(
            wide_to_string(&quote_arg(OsStr::new("say \"hi\""))),
            "\"say \\\"hi\\\"\""
        );
    }

    #[test]
    fn doubles_backslashes_before_quotes_and_closing_quote() {
        assert_eq!(
            wide_to_string(&quote_arg(OsStr::new(r#"C:\path\"quoted""#))),
            r#""C:\path\\\"quoted\"""#
        );
        assert_eq!(
            wide_to_string(&quote_arg(OsStr::new(r#"C:\path with slash\"#))),
            r#""C:\path with slash\\""#
        );
    }

    #[test]
    fn environment_block_contains_only_configured_values() {
        let env = BTreeMap::from([
            ("ZED".to_owned(), "last".to_owned()),
            ("ABC".to_owned(), "first".to_owned()),
        ]);

        let block = environment_block(&env);
        assert_eq!(
            wide_to_string(&block),
            "ABC=first\0ZED=last\0\0".to_string()
        );
    }

    #[test]
    fn empty_environment_block_is_nul_terminated() {
        assert_eq!(environment_block(&BTreeMap::new()), vec![0, 0]);
    }

    #[test]
    fn detects_programs_with_path_separators() {
        assert!(has_path_separator(OsStr::new(
            r"C:\Windows\System32\cmd.exe"
        )));
        assert!(has_path_separator(OsStr::new("bin/tool.exe")));
        assert!(!has_path_separator(OsStr::new("cmd")));
    }

    #[test]
    fn explicit_paths_bypass_the_sandbox_path_lookup() {
        let resolved = application_name(OsStr::new(r"C:\tools\probe.exe"), &BTreeMap::new())
            .expect("a program with separators is passed through");
        assert_eq!(wide_to_string(&resolved), "C:\\tools\\probe.exe\0");
    }

    #[test]
    fn bare_name_resolves_from_the_sandbox_path() {
        let dir = TempDir::new("bare-name");
        let expected = dir.path().join("guardrail-lookup.exe");
        std::fs::write(&expected, b"").expect("create candidate");

        let resolved = application_name(OsStr::new("guardrail-lookup"), &env_with_path(dir.path()))
            .expect("resolve bare name from the sandbox PATH");
        assert_eq!(
            wide_to_string(&resolved),
            format!("{}\0", expected.display())
        );
    }

    #[test]
    fn extensionless_names_match_only_their_exe_candidate() {
        let dir = TempDir::new("exe-suffix");
        std::fs::write(dir.path().join("tool"), b"").expect("create extensionless file");

        let err = application_name(OsStr::new("tool"), &env_with_path(dir.path()))
            .expect_err("an extensionless bare name must only probe tool.exe");
        assert_not_found(&err);

        std::fs::write(dir.path().join("tool.exe"), b"").expect("create exe candidate");
        let resolved = application_name(OsStr::new("tool"), &env_with_path(dir.path()))
            .expect("tool.exe satisfies the lookup");
        assert_eq!(
            wide_to_string(&resolved),
            format!("{}\0", dir.path().join("tool.exe").display())
        );
    }

    #[test]
    fn names_with_extensions_are_probed_verbatim() {
        let dir = TempDir::new("verbatim-extension");
        std::fs::write(dir.path().join("tool.cmd"), b"").expect("create candidate");

        let resolved = application_name(OsStr::new("tool.cmd"), &env_with_path(dir.path()))
            .expect("a name with an extension is probed as given");
        assert_eq!(
            wide_to_string(&resolved),
            format!("{}\0", dir.path().join("tool.cmd").display())
        );
    }

    #[test]
    fn earlier_sandbox_path_entries_win() {
        let first = TempDir::new("first-entry");
        let second = TempDir::new("second-entry");
        std::fs::write(first.path().join("dup.exe"), b"").expect("create first candidate");
        std::fs::write(second.path().join("dup.exe"), b"").expect("create second candidate");

        // An empty leading entry must be skipped, not treated as the CWD.
        let joined = format!(";{};{}", first.path().display(), second.path().display());
        let env = BTreeMap::from([("PATH".to_owned(), joined)]);

        let resolved = application_name(OsStr::new("dup"), &env).expect("resolve duplicated name");
        assert_eq!(
            wide_to_string(&resolved),
            format!("{}\0", first.path().join("dup.exe").display())
        );
    }

    #[test]
    fn path_key_is_matched_case_insensitively() {
        let dir = TempDir::new("path-key-case");
        std::fs::write(dir.path().join("cased.exe"), b"").expect("create candidate");
        let env = BTreeMap::from([("Path".to_owned(), dir.path().display().to_string())]);

        application_name(OsStr::new("cased"), &env)
            .expect("a `Path` key must satisfy the PATH lookup");
    }

    #[test]
    fn relative_sandbox_path_entries_are_rejected() {
        for relative in [".", "tools", r"C:tools", r"\tools"] {
            let env = BTreeMap::from([("PATH".to_owned(), relative.to_owned())]);
            let err = application_name(OsStr::new("tool"), &env)
                .expect_err("a relative PATH entry must be rejected");
            match err {
                Error::Spawn(io) => {
                    assert_eq!(io.kind(), io::ErrorKind::InvalidInput, "{io:?}");
                }
                other => panic!("expected an InvalidInput spawn error, got {other:?}"),
            }
        }
    }

    #[test]
    fn relative_entries_are_rejected_before_any_program_is_selected() {
        let dir = TempDir::new("absolute-before-relative");
        std::fs::write(dir.path().join("tool.exe"), b"").expect("create absolute candidate");
        let path = format!("{};.", dir.path().display());
        let env = BTreeMap::from([("PATH".to_owned(), path)]);

        let err = application_name(OsStr::new("tool"), &env)
            .expect_err("the complete PATH must be validated before lookup");
        match err {
            Error::Spawn(io) => assert_eq!(io.kind(), io::ErrorKind::InvalidInput, "{io:?}"),
            other => panic!("expected an InvalidInput spawn error, got {other:?}"),
        }
    }

    #[test]
    fn bare_names_never_use_the_parent_lookup_context() {
        // `cmd` resolves in the supervisor's context (parent PATH and the
        // system directories), but the sandbox environment has no PATH, so
        // the lookup must fail instead of falling back to that context.
        let err = application_name(OsStr::new("cmd"), &BTreeMap::new())
            .expect_err("a bare name without a sandbox PATH must not resolve");
        assert_not_found(&err);
    }

    fn env_with_path(dir: &Path) -> BTreeMap<String, String> {
        BTreeMap::from([("PATH".to_owned(), dir.display().to_string())])
    }

    fn assert_not_found(err: &Error) {
        match err {
            Error::Spawn(io) => assert_eq!(io.kind(), io::ErrorKind::NotFound, "{io:?}"),
            other => panic!("expected a NotFound spawn error, got {other:?}"),
        }
    }

    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "guardrail-windows-process-{label}-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&path).expect("create temp dir");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            // Best-effort cleanup; a leftover temp dir must not fail the test.
            let _removed = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn command_line_block_quotes_program_and_args() {
        let block = command_line_block(
            OsStr::new(r"C:\tools\probe.exe"),
            &["plain".into(), "two words".into()],
        );
        assert_eq!(
            wide_to_string(&block),
            "C:\\tools\\probe.exe plain \"two words\"\0"
        );
    }

    #[test]
    fn anon_pipe_ends_transfer_bytes_and_close_to_eof() {
        use std::fs::File;
        use std::io::{Read, Write};
        use std::process::ChildStdout;

        let (ours, theirs) = anon_pipe(true).expect("create stdio pipe");
        // The child's synchronous end behaves like a regular file handle.
        let mut writer = File::from(theirs);
        writer.write_all(b"guardrail").expect("write child end");
        drop(writer);

        // Our end is overlapped, which is exactly what ChildStdout requires.
        let mut reader = ChildStdout::from(ours);
        let mut buffer = Vec::new();
        reader.read_to_end(&mut buffer).expect("read parent end");
        assert_eq!(buffer, b"guardrail");
    }

    #[test]
    fn prepared_stdio_handles_are_not_inheritable_in_host() {
        use windows_sys::Win32::Foundation::{GetHandleInformation, HANDLE_FLAG_INHERIT};

        let stdio = prepare_stdio(StdioMode::Null, StdioMode::Piped, StdioMode::Piped)
            .expect("prepare stdio");
        for handle in [&stdio.child_stdin, &stdio.child_stdout, &stdio.child_stderr] {
            let mut flags = 0;
            // SAFETY: handle is live and flags is a valid out-pointer.
            let queried = unsafe { GetHandleInformation(handle.as_raw_handle(), &mut flags) };
            assert_ne!(queried, 0, "query handle flags");
            assert_eq!(
                flags & HANDLE_FLAG_INHERIT,
                0,
                "host-side stdio sources must remain non-inheritable"
            );
        }
    }

    #[test]
    fn null_device_accepts_reads_and_writes() {
        use std::fs::File;
        use std::io::{Read, Write};

        let mut writable = File::from(open_null(StreamDirection::Write).expect("open NUL"));
        writable.write_all(b"discarded").expect("write NUL");

        let mut readable = File::from(open_null(StreamDirection::Read).expect("open NUL"));
        let mut buffer = [0u8; 4];
        assert_eq!(readable.read(&mut buffer).expect("read NUL"), 0);
    }
}
