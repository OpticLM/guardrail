//! Suspended Windows process launch under a Job Object.

#![cfg(windows)]

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, OwnedHandle};
use std::process::Command;
use std::{mem, ptr};

use guardrail_core::{Error, SandboxChild};
use windows_sys::Win32::System::JobObjects::{AssignProcessToJobObject, TerminateJobObject};
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW, PROCESS_INFORMATION,
    STARTUPINFOW, TerminateProcess,
};

use crate::handle::{bool_result, owned_handle_from_raw, resume_then_close_thread};

pub(crate) fn launch(command: Command, job: OwnedHandle) -> Result<SandboxChild, Error> {
    let mut command_line = command_line_block(&command);
    let environment = environment_block(&command);
    let cwd = command
        .get_current_dir()
        .map(|path| wide_null(path.as_os_str()));
    let cwd_ptr = cwd.as_ref().map_or(ptr::null(), |wide| wide.as_ptr());

    let startup = STARTUPINFOW {
        cb: mem::size_of::<STARTUPINFOW>() as u32,
        ..STARTUPINFOW::default()
    };
    let mut process_info = PROCESS_INFORMATION::default();

    // SAFETY: all pointers either are null or point to nul-terminated UTF-16
    // buffers that outlive the call. `command_line` is mutable because
    // CreateProcessW may rewrite its command-line buffer.
    let created = unsafe {
        CreateProcessW(
            ptr::null(),
            command_line.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            0,
            CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
            environment.as_ptr().cast(),
            cwd_ptr,
            &startup,
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
    // SAFETY: the owned process handle, owned job handle, and pid all come
    // from the successful CreateProcessW + AssignProcessToJobObject sequence
    // above and are transferred into SandboxChild.
    Ok(unsafe { SandboxChild::from_windows_handles(process, job, pid) })
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
    fn empty_environment_block_is_double_nul_terminated() {
        let mut command = Command::new("cmd");
        command.env_clear();

        assert_eq!(environment_block(&command), vec![0, 0]);
    }
}
