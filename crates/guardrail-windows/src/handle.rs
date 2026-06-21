//! Small helpers for Windows raw handle APIs.

#![cfg(windows)]

use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Threading::ResumeThread;
use windows_sys::core::BOOL;

pub(crate) fn bool_result(ok: BOOL) -> io::Result<()> {
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(crate) unsafe fn owned_handle_from_raw(handle: HANDLE) -> io::Result<OwnedHandle> {
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: the caller guarantees that `handle` is valid, uniquely owned,
    // and must be closed by this process. Null and INVALID_HANDLE_VALUE were
    // rejected above.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

pub(crate) fn resume_then_close_thread(thread: OwnedHandle) -> io::Result<()> {
    // SAFETY: `thread` is the primary thread handle returned by CreateProcessW.
    // ResumeThread borrows the handle; dropping `thread` closes it immediately
    // after this call.
    let previous_count = unsafe { ResumeThread(thread.as_raw_handle()) };
    if previous_count == u32::MAX {
        return Err(io::Error::last_os_error());
    }
    drop(thread);
    Ok(())
}
