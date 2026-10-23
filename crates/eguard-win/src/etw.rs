//! Process starts as they happen (spec section 7): a real-time ETW session on `Microsoft-Windows-Kernel-Process`,
//! so a blocked game is seen the moment it starts rather than at the next sweep. Only the new process's id is read
//! from each event; the rest (its path, signer) is looked up from outside like any other process.
//!
//! Starting the session needs an administrator or SYSTEM; without one, `spawn` fails and the sweep alone finds new
//! processes (within its interval).
#![allow(unsafe_code)]

use crate::wide::wide;
use std::ptr::null;
use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, ERROR_SUCCESS};
use windows_sys::Win32::System::Diagnostics::Etw::{
    CONTROLTRACE_HANDLE, ControlTraceW, EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_RECORD, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW,
    EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE, EnableTraceEx2, OpenTraceW, PROCESS_TRACE_MODE_EVENT_RECORD,
    PROCESS_TRACE_MODE_REAL_TIME, ProcessTrace, StartTraceW, TRACE_LEVEL_INFORMATION, WNODE_FLAG_TRACED_GUID,
};

/// `Microsoft-Windows-Kernel-Process`.
const KERNEL_PROCESS: windows_sys::core::GUID = windows_sys::core::GUID::from_u128(0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716);
/// `WINEVENT_KEYWORD_PROCESS`: process starts and stops only.
const KEYWORD_PROCESS: u64 = 0x10;
/// The `ProcessStart` event; its data begins with the new process's id (a `u32`).
const PROCESS_START: u16 = 1;
const SESSION_NAME: &str = "eGuard-ProcessStart";
const INVALID_TRACE: u64 = u64::MAX;

type OnStart = Box<dyn Fn(u32) + Send + Sync>;

/// `EVENT_TRACE_PROPERTIES` followed by room for the session's name, as `StartTraceW` and `ControlTraceW` want it.
fn properties(name_len: usize) -> Vec<u64> {
    let bytes = size_of::<EVENT_TRACE_PROPERTIES>() + (name_len + 1) * 2;
    let mut buf = vec![0u64; bytes.div_ceil(8)];
    // SAFETY: `buf` is at least the struct's size and 8-aligned; the struct is plain data.
    let p = unsafe { &mut *buf.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>() };
    p.Wnode.BufferSize = bytes as u32;
    p.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    // QueryPerformanceCounter timestamps: cheap, and only the order matters here
    p.Wnode.ClientContext = 1;
    p.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    p.LoggerNameOffset = size_of::<EVENT_TRACE_PROPERTIES>() as u32;
    buf
}

fn is_kernel_process(g: &windows_sys::core::GUID) -> bool {
    (g.data1, g.data2, g.data3, g.data4) == (KERNEL_PROCESS.data1, KERNEL_PROCESS.data2, KERNEL_PROCESS.data3, KERNEL_PROCESS.data4)
}

unsafe extern "system" fn on_event(record: *mut EVENT_RECORD) {
    // SAFETY: ETW passes a valid record for the duration of the call; `UserContext` is the `OnStart` leaked in
    // `spawn`, alive for the life of the process. The data is read only after checking its length.
    unsafe {
        let r = &*record;
        if !is_kernel_process(&r.EventHeader.ProviderId) || r.EventHeader.EventDescriptor.Id != PROCESS_START || r.UserDataLength < 4 {
            return;
        }
        let pid = r.UserData.cast::<u32>().read_unaligned();
        let f = &*r.UserContext.cast::<OnStart>();
        f(pid);
    }
}

/// Starts watching for process starts; `on_start(pid)` is called on the watcher's thread for each one.
pub fn spawn(on_start: impl Fn(u32) + Send + Sync + 'static) -> std::io::Result<()> {
    let name = wide(SESSION_NAME);
    let mut handle = CONTROLTRACE_HANDLE { Value: 0 };
    let mut props = properties(SESSION_NAME.len());
    // SAFETY: `props` is laid out as `properties` describes; `name` is zero-terminated.
    let mut rc = unsafe { StartTraceW(&raw mut handle, name.as_ptr(), props.as_mut_ptr().cast()) };
    if rc == ERROR_ALREADY_EXISTS {
        // Left over from an earlier run that didn't stop it: stop it and start afresh
        let mut stop = properties(SESSION_NAME.len());
        // SAFETY: as above.
        unsafe { ControlTraceW(CONTROLTRACE_HANDLE { Value: 0 }, name.as_ptr(), stop.as_mut_ptr().cast(), EVENT_TRACE_CONTROL_STOP) };
        props = properties(SESSION_NAME.len());
        // SAFETY: as above.
        rc = unsafe { StartTraceW(&raw mut handle, name.as_ptr(), props.as_mut_ptr().cast()) };
    }
    if rc != ERROR_SUCCESS {
        return Err(std::io::Error::from_raw_os_error(rc as i32));
    }
    // SAFETY: `handle` is the session just started; no filter parameters.
    let rc = unsafe {
        EnableTraceEx2(
            handle,
            &KERNEL_PROCESS,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            TRACE_LEVEL_INFORMATION as u8,
            KEYWORD_PROCESS,
            0,
            0,
            null(),
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(std::io::Error::from_raw_os_error(rc as i32));
    }

    // The callback's context lives as long as the process: the session is never closed while eGuard runs
    let context: &'static OnStart = Box::leak(Box::new(Box::new(on_start) as OnStart));
    let mut logger = name.clone();
    let mut log = EVENT_TRACE_LOGFILEW { LoggerName: logger.as_mut_ptr(), ..Default::default() };
    log.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    log.Anonymous2.EventRecordCallback = Some(on_event);
    log.Context = std::ptr::from_ref(context).cast_mut().cast();
    // SAFETY: `log` is filled in for a real-time session by name; `logger` outlives the call.
    let trace = unsafe { OpenTraceW(&raw mut log) };
    if trace.Value == INVALID_TRACE {
        return Err(crate::last_error());
    }
    std::thread::Builder::new().name("etw".into()).spawn(move || {
        // SAFETY: one valid trace handle; no time window (real time). Blocks while the session runs.
        unsafe { ProcessTrace(&raw const trace, 1, null(), null()) };
        // The session's name and properties were in use until here
        drop((logger, props));
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;

    #[test]
    fn sees_a_process_start_when_allowed_to() {
        let (tx, rx) = mpsc::channel();
        let tx = std::sync::Mutex::new(tx);
        match spawn(move |pid| {
            let _ = tx.lock().map(|t| t.send(pid));
        }) {
            // Not an administrator (the usual case for `cargo test`): the sweep covers, nothing to check here
            Err(e) if e.raw_os_error() == Some(5) => {}
            Err(e) => panic!("{e}"),
            Ok(()) => {
                std::thread::sleep(Duration::from_millis(500));
                let mut child = std::process::Command::new("cmd.exe").args(["/c", "exit"]).spawn().unwrap();
                let want = child.id();
                child.wait().unwrap();
                let seen = (0..50).any(|_| rx.recv_timeout(Duration::from_millis(100)).is_ok_and(|pid| pid == want));
                assert!(seen, "ETW didn't report pid {want}");
            }
        }
    }
}
