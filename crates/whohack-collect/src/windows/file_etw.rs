//! Kernel-File TDH schemas: file names and successful I/O completions only.
//! Never dereference kernel pointers or inspect the file's bytes.
use super::{
    etw::{DevicePaths, Slot, event_ts, send},
    identity,
};
use crate::{
    files::{Change, FileSignals},
    health::Health,
};
use ferrisetw::{
    EventRecord,
    parser::{Parser, Pointer},
    schema_locator::SchemaLocator,
};
use lru::LruCache;
use std::{
    num::NonZeroUsize,
    sync::{Arc, Mutex},
};
use whohack_core::{Os, config::SensitiveConfig};

pub const PROVIDER: u128 = 0xedd08927_9cc4_4e65_b970_c2560fb5c289;
// FileName, FileIO, OperationEnd, Create, Read, Write, RenamePath.
pub const KEYWORDS: u64 = 0x10 | 0x20 | 0x40 | 0x80 | 0x100 | 0x200 | 0x800;
const CACHE_SIZE: usize = 8192;
const NAME_TTL: i64 = 120_000;
const IO_TTL: i64 = 10_000;

enum Operation {
    Open {
        object: u64,
        path: String,
    },
    Access {
        pid: u32,
        born: i64,
        id: u64,
        path: String,
        change: Change,
    },
}
struct State {
    names: LruCache<(bool, u64), (i64, String)>,
    pending: LruCache<u64, (i64, Operation)>,
    signals: FileSignals,
    loss_seen: u64,
}
impl State {
    fn new(sensitive: &SensitiveConfig) -> Self {
        Self {
            names: LruCache::new(NonZeroUsize::new(CACHE_SIZE).unwrap()),
            pending: LruCache::new(NonZeroUsize::new(CACHE_SIZE).unwrap()),
            signals: FileSignals::new(Os::Windows, sensitive),
            loss_seen: 0,
        }
    }
    fn remember(&mut self, object: bool, id: u64, ts: i64, path: String) {
        if id != 0 && !path.is_empty() && path.len() <= 4096 {
            self.names.put((object, id), (ts, path));
        }
    }
    fn name(&mut self, object: u64, key: u64, ts: i64) -> Option<String> {
        for id in [(false, key), (true, object)] {
            if let Some((seen, path)) = self.names.get(&id)
                && (0..=NAME_TTL).contains(&ts.saturating_sub(*seen))
            {
                return Some(path.clone());
            }
        }
        None
    }
}

fn pointer(parser: &Parser<'_, '_>, name: &str) -> Option<u64> {
    parser.try_parse::<Pointer>(name).ok().map(|p| *p as u64)
}

pub fn callback(
    slot: Slot,
    devices: Arc<DevicePaths>,
    sensitive: &SensitiveConfig,
    health: Arc<Health>,
) -> impl Fn(&EventRecord, &SchemaLocator) + Send + Sync + 'static {
    let state = Mutex::new(State::new(sensitive));
    move |record, locator| {
        use std::sync::atomic::Ordering;
        let event_id = record.event_id();
        if !matches!(event_id, 10..=16 | 24 | 27) {
            return;
        }
        let Ok(schema) = locator.event_schema(record) else {
            health.unattributed();
            return;
        };
        let p = Parser::create(record, &schema);
        let Ok(mut state) = state.lock() else {
            return;
        };
        let lost = health.kernel_lost.load(Ordering::Relaxed);
        if lost != state.loss_seen {
            state.names.clear();
            state.pending.clear();
            state.loss_seen = lost;
        }
        let ts = event_ts(record);
        if event_id == 10 {
            if let (Some(key), Ok(path)) =
                (pointer(&p, "FileKey"), p.try_parse::<String>("FileName"))
            {
                state.remember(false, key, ts, devices.to_dos(&path));
            }
            return;
        }
        if event_id == 11 {
            if let Some(key) = pointer(&p, "FileKey") {
                state.names.pop(&(false, key));
            }
            return;
        }
        if matches!(event_id, 13 | 14) {
            if let Some(object) = pointer(&p, "FileObject") {
                state.names.pop(&(true, object));
            }
            return;
        }
        let Some(irp) = pointer(&p, "Irp").filter(|id| *id != 0) else {
            return;
        };
        if event_id == 24 {
            let Some((begin, operation)) = state.pending.pop(&irp) else {
                return;
            };
            // Failed, pending, truncated, and stale operations provide no evidence.
            if p.try_parse::<u32>("Status").ok() != Some(0)
                || !(0..=IO_TTL).contains(&ts.saturating_sub(begin))
            {
                return;
            }
            match operation {
                Operation::Open { object, path } => state.remember(true, object, ts, path),
                Operation::Access {
                    pid,
                    born,
                    id,
                    path,
                    change,
                } => {
                    if identity::process_birth(pid, record.raw_timestamp() as u64) != Some(born) {
                        health.unattributed();
                        return;
                    }
                    for event in state.signals.access(pid, born, begin, id, &path, change) {
                        send(&slot, event);
                    }
                }
            }
            return;
        }
        if event_id == 12 {
            if let (Some(object), Ok(path)) =
                (pointer(&p, "FileObject"), p.try_parse::<String>("FileName"))
            {
                let path = devices.to_dos(&path);
                if path.len() <= 4096 {
                    state
                        .pending
                        .put(irp, (ts, Operation::Open { object, path }));
                }
            }
            return;
        }
        let object = pointer(&p, "FileObject").unwrap_or(0);
        let key = pointer(&p, "FileKey").unwrap_or(0);
        let path = if event_id == 27 {
            p.try_parse::<String>("FilePath")
                .ok()
                .map(|s| devices.to_dos(&s))
        } else {
            state.name(object, key, ts)
        };
        let Some(path) = path.filter(|p| !p.is_empty() && p.len() <= 4096) else {
            health.unattributed();
            return;
        };
        if event_id != 27 && p.try_parse::<u32>("IOSize").unwrap_or(0) == 0 {
            return;
        }
        let tid = p
            .try_parse::<u32>("IssuingThreadId")
            .ok()
            .or_else(|| pointer(&p, "ThreadId").and_then(|id| id.try_into().ok()));
        let Some((pid, born)) =
            tid.and_then(|t| identity::thread_owner(t, record.raw_timestamp() as u64))
        else {
            health.unattributed();
            return;
        };
        let change = match event_id {
            15 => Change::Read,
            16 => Change::Write,
            27 => Change::Rename,
            _ => return,
        };
        if change == Change::Rename {
            // Invalidate until a fresh name event establishes the new binding.
            state.names.pop(&(true, object));
            state.names.pop(&(false, key));
        }
        let id = if key != 0 { key } else { object };
        if id == 0 {
            return;
        }
        if state.pending.len() == CACHE_SIZE {
            health.unattributed();
        }
        state.pending.put(
            irp,
            (
                ts,
                Operation::Access {
                    pid,
                    born,
                    id,
                    path,
                    change,
                },
            ),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn name_cache_expires_and_never_confuses_object_with_key() {
        let mut s = State::new(&Default::default());
        s.remember(false, 1, 10, "a".into());
        s.remember(true, 1, 10, "b".into());
        assert_eq!(s.name(1, 0, 11).as_deref(), Some("b"));
        assert_eq!(s.name(0, 1, 11).as_deref(), Some("a"));
        assert!(s.name(1, 1, NAME_TTL + 11).is_none());
        for id in 2..10_000 {
            s.remember(true, id, 10, "x".into());
        }
        assert_eq!(s.names.len(), CACHE_SIZE);
        assert!(s.name(1, 1, 11).is_none());
    }
}
