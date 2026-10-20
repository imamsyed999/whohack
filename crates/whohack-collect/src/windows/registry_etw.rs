//! Successful SetValue events at persistence locations. Value data is never parsed.
use super::{
    etw::{Slot, event_ts, send},
    identity,
};
use crate::health::Health;
use ferrisetw::{EventRecord, parser::Parser, schema_locator::SchemaLocator};
use std::sync::Arc;
use whohack_core::{Event, EventKind, Os, config::SensitiveConfig};
use whohack_tags::sensitive::SensitivePaths;

pub const PROVIDER: u128 = 0x70eb4f03_c1de_4f73_a051_33d13d5413bd;
pub fn callback(
    slot: Slot,
    sensitive: &SensitiveConfig,
    health: Arc<Health>,
) -> impl Fn(&EventRecord, &SchemaLocator) + Send + Sync + 'static {
    let paths = SensitivePaths::new(Os::Windows, sensitive);
    move |record, locator| {
        if record.event_id() != 5 {
            return;
        }
        let Ok(schema) = locator.event_schema(record) else {
            health.unattributed();
            return;
        };
        let p = Parser::create(record, &schema);
        if p.try_parse::<u32>("Status").ok() != Some(0) {
            return;
        }
        let (Ok(key), Ok(value)) = (
            p.try_parse::<String>("KeyName"),
            p.try_parse::<String>("ValueName"),
        ) else {
            return;
        };
        if key.len() + value.len() > 4096 {
            return;
        }
        let Some(location) = paths.persistence(&key) else {
            return;
        };
        let pid = record.process_id();
        if identity::process_birth(pid, record.raw_timestamp() as u64).is_none() {
            health.unattributed();
            return;
        }
        send(
            &slot,
            Event {
                ts: event_ts(record),
                pid,
                kind: EventKind::Persistence {
                    location,
                    target: format!("{key}\\{value}"),
                },
            },
        );
    }
}
