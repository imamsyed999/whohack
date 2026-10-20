//! Read-only session statistics. Never stops or reconfigures another trace.
use windows_sys::Win32::System::Diagnostics::Etw::*;

pub fn query(name: &str) -> Option<u64> {
    #[repr(C)]
    struct Buffer {
        properties: EVENT_TRACE_PROPERTIES,
        name: [u16; 1024],
        file: [u16; 1024],
    }
    // SAFETY: zero is a valid initial state; offsets point inside this aligned
    // allocation and the API receives the complete buffer size.
    unsafe {
        let mut b: Buffer = std::mem::zeroed();
        b.properties.Wnode.BufferSize = std::mem::size_of::<Buffer>() as u32;
        b.properties.LoggerNameOffset = std::mem::offset_of!(Buffer, name) as u32;
        b.properties.LogFileNameOffset = std::mem::offset_of!(Buffer, file) as u32;
        let name: Vec<u16> = name.encode_utf16().chain([0]).collect();
        if ControlTraceW(
            CONTROLTRACE_HANDLE { Value: 0 },
            name.as_ptr(),
            &mut b.properties,
            EVENT_TRACE_CONTROL_QUERY,
        ) != 0
        {
            return None;
        }
        Some(u64::from(b.properties.EventsLost) + u64::from(b.properties.RealTimeBuffersLost))
    }
}
