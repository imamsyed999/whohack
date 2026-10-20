//! Optional read-only subscription to an already installed/configured Sysmon.
//! Uses payload UtcTime, not log receipt time, to reject reused source PIDs.
use super::{OwnedHandle, filetime_to_unix_ms, filetime_u64, identity};
use crate::health::Health;
use anyhow::{Context, Result, ensure};
use async_trait::async_trait;
use std::{
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use tokio::sync::mpsc;
use whohack_core::{Event, EventKind};
use windows_sys::Win32::{
    Foundation::*,
    System::{EventLog::*, Threading::*, Time::SystemTimeToFileTime},
};

const CHANNEL: &str = "Microsoft-Windows-Sysmon/Operational";
const QUERY: &str = "*[System[Provider[@Name='Microsoft-Windows-Sysmon'] and EventID=8]]";
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}
struct Handle(EVT_HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe {
                EvtClose(self.0);
            }
        }
    }
}

#[derive(Debug)]
pub struct Sysmon {
    health: Arc<Health>,
}
impl Sysmon {
    pub fn new(health: Arc<Health>) -> Result<Self> {
        // Query a channel that already exists; no driver install or policy writes.
        let h = Handle(unsafe {
            EvtQuery(
                0,
                wide(CHANNEL).as_ptr(),
                wide(QUERY).as_ptr(),
                EvtQueryChannelPath,
            )
        });
        ensure!(
            h.0 != 0,
            "Sysmon channel unavailable: {}",
            std::io::Error::last_os_error()
        );
        Ok(Self { health })
    }
}

fn utc_filetime(s: &str) -> Option<u64> {
    if !s.is_ascii() {
        return None;
    }
    if s.len() != 23
        || &s[4..5] != "-"
        || &s[7..8] != "-"
        || &s[10..11] != " "
        || &s[13..14] != ":"
        || &s[16..17] != ":"
        || &s[19..20] != "."
    {
        return None;
    }
    let st = SYSTEMTIME {
        wYear: s.get(0..4)?.parse().ok()?,
        wMonth: s.get(5..7)?.parse().ok()?,
        wDay: s.get(8..10)?.parse().ok()?,
        wHour: s.get(11..13)?.parse().ok()?,
        wMinute: s.get(14..16)?.parse().ok()?,
        wSecond: s.get(17..19)?.parse().ok()?,
        wMilliseconds: s.get(20..23)?.parse().ok()?,
        wDayOfWeek: 0,
    };
    let mut ft = FILETIME::default();
    if unsafe { SystemTimeToFileTime(&st, &mut ft) } == 0 {
        return None;
    }
    Some(filetime_u64(&ft))
}

fn string_value(v: &EVT_VARIANT, buf: &[u64], used: usize) -> Option<String> {
    if v.Type != EvtVarTypeString as u32 {
        return None;
    }
    let start = buf.as_ptr() as usize;
    let end = start.checked_add(used.min(std::mem::size_of_val(buf)))?;
    // SAFETY: variant type and complete pointer range/alignment are checked.
    let ptr = unsafe { v.Anonymous.StringVal };
    let addr = ptr as usize;
    if addr < start || addr >= end || !addr.is_multiple_of(2) {
        return None;
    }
    let units = unsafe { std::slice::from_raw_parts(ptr, ((end - addr) / 2).min(4097)) };
    let len = units.iter().position(|u| *u == 0)?;
    String::from_utf16(&units[..len]).ok()
}

fn render(context: &Handle, event: &Handle) -> Result<Option<Event>> {
    let mut used = 0;
    let mut count = 0;
    unsafe {
        EvtRender(
            context.0,
            event.0,
            EvtRenderEventValues,
            0,
            std::ptr::null_mut(),
            &mut used,
            &mut count,
        );
    }
    ensure!(
        used > 0 && used <= 64 * 1024,
        "Sysmon record exceeded render bound"
    );
    let mut buf = vec![0u64; (used as usize).div_ceil(8)];
    let ok = unsafe {
        EvtRender(
            context.0,
            event.0,
            EvtRenderEventValues,
            (buf.len() * 8) as u32,
            buf.as_mut_ptr().cast(),
            &mut used,
            &mut count,
        )
    };
    ensure!(
        ok != 0 && count == 3 && used as usize >= 3 * std::mem::size_of::<EVT_VARIANT>(),
        "Sysmon event render failed"
    );
    // SAFETY: aligned buffer and all three complete variants are in bounds.
    let values = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<EVT_VARIANT>(), 3) };
    let strings: Option<Vec<_>> = values
        .iter()
        .map(|v| string_value(v, &buf, used as usize))
        .collect();
    let Some(strings) = strings else {
        return Ok(None);
    };
    let (Ok(pid), Ok(target_pid), Some(ft)) = (
        strings[0].parse::<u32>(),
        strings[1].parse::<u32>(),
        utc_filetime(&strings[2]),
    ) else {
        return Ok(None);
    };
    if pid == target_pid || target_pid == 0 || identity::process_birth(pid, ft).is_none() {
        return Ok(None);
    }
    Ok(Some(Event {
        ts: filetime_to_unix_ms(ft),
        pid,
        kind: EventKind::Injection { target_pid },
    }))
}

fn collect(tx: mpsc::Sender<Event>, health: Arc<Health>) -> Result<()> {
    // Event-log handles stay on this one blocking worker thread.
    let signal = OwnedHandle(unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) });
    ensure!(!signal.0.is_null(), "create Sysmon signal");
    let subscription = Handle(unsafe {
        EvtSubscribe(
            0,
            signal.0,
            wide(CHANNEL).as_ptr(),
            wide(QUERY).as_ptr(),
            0,
            std::ptr::null(),
            None,
            EvtSubscribeToFutureEvents | EvtSubscribeStrict,
        )
    });
    ensure!(
        subscription.0 != 0,
        "subscribe to Sysmon: {}",
        std::io::Error::last_os_error()
    );
    let paths = [
        wide("Event/EventData/Data[@Name='SourceProcessId']"),
        wide("Event/EventData/Data[@Name='TargetProcessId']"),
        wide("Event/EventData/Data[@Name='UtcTime']"),
    ];
    let pointers: Vec<_> = paths.iter().map(|p| p.as_ptr()).collect();
    let context =
        Handle(unsafe { EvtCreateRenderContext(3, pointers.as_ptr(), EvtRenderContextValues) });
    ensure!(context.0 != 0, "Sysmon render context");
    health.injection.store(true, Ordering::Relaxed);
    while !tx.is_closed() {
        let wait =
            unsafe { WaitForSingleObject(signal.0, Duration::from_millis(250).as_millis() as u32) };
        if wait == WAIT_TIMEOUT {
            continue;
        }
        ensure!(wait == WAIT_OBJECT_0, "Sysmon wait failed");
        unsafe {
            ResetEvent(signal.0);
        }
        loop {
            let mut events = [0; 16];
            let mut count = 0;
            let ok = unsafe {
                EvtNext(
                    subscription.0,
                    events.len() as u32,
                    events.as_mut_ptr(),
                    0,
                    0,
                    &mut count,
                )
            };
            if ok == 0 {
                let error = unsafe { GetLastError() };
                ensure!(
                    error == ERROR_NO_MORE_ITEMS,
                    "Sysmon subscription failed: {error}"
                );
                break;
            }
            // Own all returned handles before parsing so errors cannot leak them.
            let events: Vec<_> = events[..count as usize]
                .iter()
                .copied()
                .map(Handle)
                .collect();
            for event in events {
                match render(&context, &event) {
                    Ok(Some(event)) => {
                        if let Err(mpsc::error::TrySendError::Full(_)) = tx.try_send(event) {
                            health.dropped.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    Ok(None) | Err(_) => health.unattributed(),
                }
            }
            if tx.is_closed() {
                break;
            }
        }
    }
    health.injection.store(false, Ordering::Relaxed);
    Ok(())
}

#[async_trait]
impl crate::Collector for Sysmon {
    fn name(&self) -> &'static str {
        "windows-sysmon"
    }
    async fn run(&self, tx: mpsc::Sender<Event>) -> Result<()> {
        let health = self.health.clone();
        let result = tokio::task::spawn_blocking(move || collect(tx, health))
            .await
            .context("Sysmon worker")?;
        self.health.injection.store(false, Ordering::Relaxed);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_bad_dates_and_decodes_payload_utc() {
        assert_eq!(
            filetime_to_unix_ms(utc_filetime("1970-01-01 00:00:00.123").unwrap()),
            123
        );
        for s in [
            "garbage",
            "2026-99-99 00:00:00.000",
            "2026-01-01 00:00:00.000Z",
            "界界界界界界界a",
        ] {
            assert!(utc_filetime(s).is_none());
        }
    }
}
