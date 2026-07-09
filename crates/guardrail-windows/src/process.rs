//! Suspended Windows process launch under a Job Object.

#![cfg(windows)]

use std::any::Any;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, OwnedHandle};
use std::process::Command;
use std::sync::Arc;
use std::{io, mem, ptr};

use guardrail_core::{Error, NetworkPolicy, Result, SandboxChild};
use windows_sys::Win32::Security::SECURITY_CAPABILITIES;
use windows_sys::Win32::Storage::FileSystem::SearchPathW;
use windows_sys::Win32::System::JobObjects::{AssignProcessToJobObject, TerminateJobObject};
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW, DeleteProcThreadAttributeList,
    EXTENDED_STARTUPINFO_PRESENT, InitializeProcThreadAttributeList,
    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, PROCESS_INFORMATION, STARTUPINFOEXW,
    TerminateProcess, UpdateProcThreadAttribute,
};

use crate::cache::{CachedAppContainer, raw_security_capabilities};
use crate::handle::{bool_result, owned_handle_from_raw, resume_then_close_thread};

pub(crate) fn launch(
    command: Command,
    job: OwnedHandle,
    appcontainer: Arc<CachedAppContainer>,
    network: NetworkPolicy,
) -> Result<SandboxChild> {
    let mut command_line = command_line_block(&command);
    let environment = environment_block(&command);
    let application_name = application_name(&command);
    let application_name_ptr = application_name
        .as_ref()
        .map_or(ptr::null(), |wide| wide.as_ptr());
    let cwd = command
        .get_current_dir()
        .map(|path| wide_null(path.as_os_str()));
    let cwd_ptr = cwd.as_ref().map_or(ptr::null(), |wide| wide.as_ptr());

    let mut startup = STARTUPINFOEXW {
        StartupInfo: windows_sys::Win32::System::Threading::STARTUPINFOW {
            cb: mem::size_of::<STARTUPINFOEXW>() as u32,
            ..windows_sys::Win32::System::Threading::STARTUPINFOW::default()
        },
        ..STARTUPINFOEXW::default()
    };
    let mut attributes =
        AttributeList::new(1).map_err(|err| Error::confinement("appcontainer", err))?;
    let mut security_capabilities = appcontainer.security_capabilities(network)?;
    attributes
        .update_security_capabilities(raw_security_capabilities(&mut security_capabilities))
        .map_err(|err| Error::confinement("appcontainer", err))?;
    startup.lpAttributeList = attributes.as_mut_ptr();

    let mut process_info = PROCESS_INFORMATION::default();

    // SAFETY: all pointers either are null or point to nul-terminated UTF-16
    // buffers that outlive the call. `command_line` is mutable because
    // CreateProcessW may rewrite its command-line buffer. The extended startup
    // attribute list and SECURITY_CAPABILITIES outlive the call.
    let created = unsafe {
        CreateProcessW(
            application_name_ptr,
            command_line.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            0,
            CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
            environment.as_ptr().cast(),
            cwd_ptr,
            &startup.StartupInfo,
            &mut process_info,
        )
    };
    bool_result(created).map_err(Error::Spawn)?;

    let process = unsafe { owned_handle_from_raw(process_info.hProcess) }.map_err(Error::Spawn)?;
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
    let guards: Vec<Box<dyn Any + Send>> = vec![Box::new(appcontainer)];
    // SAFETY: the owned process handle, owned job handle, and pid all come
    // from the successful CreateProcessW + AssignProcessToJobObject sequence
    // above and are transferred into SandboxChild. The cleanup guards only own
    // AppContainer/ACL cleanup state and are dropped after the raw handles.
    Ok(unsafe { SandboxChild::from_windows_handles_with_guards(process, job, pid, guards) })
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

fn command_line_block(command: &Command) -> Vec<u16> {
    let mut out = quote_arg(command.get_program());
    for arg in command.get_args() {
        out.push(b' ' as u16);
        out.extend(quote_arg(arg));
    }
    out.push(0);
    out
}

fn application_name(command: &Command) -> Option<Vec<u16>> {
    let program = command.get_program();
    if has_path_separator(program) {
        return Some(wide_null(program));
    }

    let program_wide = wide_null(program);
    let extension = wide_null(OsStr::new(".exe"));
    let mut buffer = vec![0u16; 260];

    loop {
        let found = unsafe {
            SearchPathW(
                ptr::null(),
                program_wide.as_ptr(),
                extension.as_ptr(),
                buffer.len() as u32,
                buffer.as_mut_ptr(),
                ptr::null_mut(),
            )
        };
        if found == 0 {
            return None;
        }

        let found = found as usize;
        if found < buffer.len() {
            buffer.truncate(found + 1);
            return Some(buffer);
        }

        buffer.resize(found + 1, 0);
    }
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

fn environment_block(command: &Command) -> Vec<u16> {
    let mut entries = command
        .get_envs()
        .filter_map(|(key, value)| value.map(|value| (key, value)))
        .collect::<Vec<_>>();
    entries.sort_by_key(|(key, _)| key.to_string_lossy().to_ascii_uppercase());

    let mut block = Vec::new();
    for (key, value) in entries {
        block.extend(key.encode_wide());
        block.push(b'=' as u16);
        block.extend(value.encode_wide());
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
    fn environment_block_contains_only_explicit_values() {
        let mut command = Command::new("cmd");
        command.env_clear();
        command.env("ZED", "last");
        command.env("ABC", "first");

        let block = environment_block(&command);
        assert_eq!(
            wide_to_string(&block),
            "ABC=first\0ZED=last\0\0".to_string()
        );
    }

    #[test]
    fn empty_environment_block_is_nul_terminated() {
        let mut command = Command::new("cmd");
        command.env_clear();

        assert_eq!(environment_block(&command), vec![0, 0]);
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
    fn resolves_bare_program_with_parent_search_path() {
        let command = Command::new("cmd");
        let resolved = application_name(&command).expect("cmd resolves");
        let resolved = wide_to_string(&resolved);
        assert!(resolved.to_ascii_lowercase().contains(r"\cmd.exe"));
        assert!(resolved.ends_with('\0'));
    }
}
