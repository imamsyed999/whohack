//! `events` table plus the derived `connections` and `dns` rows.

use rusqlite::{Connection, params};

use super::{Store, StoreError, from_json};
use crate::types::{Event, EventKind};

/// Inserts one event and its derived rows on an open connection/transaction.
fn insert_on(conn: &Connection, e: &Event) -> Result<i64, StoreError> {
    conn.prepare_cached("INSERT INTO events (ts, pid, kind, data) VALUES (?1, ?2, ?3, ?4)")?
        .execute(params![
            e.ts,
            e.pid,
            e.kind.name(),
            serde_json::to_string(&e.kind)?
        ])?;
    let event_id = conn.last_insert_rowid();
    match &e.kind {
        EventKind::NetConnect {
            remote_ip,
            remote_port,
            proto,
            domain,
            dns_before,
        } => {
            conn.prepare_cached(
                "INSERT INTO connections
                     (event_id, ts, pid, remote_ip, remote_port, proto, domain, dns_before)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )?
            .execute(params![
                event_id,
                e.ts,
                e.pid,
                remote_ip.to_string(),
                remote_port,
                proto.as_str(),
                domain,
                dns_before,
            ])?;
        }
        EventKind::DnsQuery { name, answers } => {
            let mut stmt = conn.prepare_cached(
                "INSERT INTO dns (event_id, ts, pid, name, answer) VALUES (?1, ?2, ?3, ?4, ?5)",
            )?;
            if answers.is_empty() {
                stmt.execute(params![event_id, e.ts, e.pid, name, None::<String>])?;
            }
            for a in answers {
                stmt.execute(params![event_id, e.ts, e.pid, name, a.to_string()])?;
            }
        }
        _ => {}
    }
    Ok(event_id)
}

impl Store {
    /// Stores an event. `NetConnect` also writes a `connections` row and
    /// `DnsQuery` writes one `dns` row per answer (one NULL-answer row if
    /// there are none), all in one transaction. Returns the event row id.
    pub fn insert_event(&self, e: &Event) -> Result<i64, StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        let id = insert_on(&tx, e)?;
        tx.commit()?;
        Ok(id)
    }

    /// Stores many events in a single transaction (the service's writer
    /// batches per tick to keep idle CPU low). Returns the number stored.
    pub fn insert_events(&self, events: &[Event]) -> Result<usize, StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        for e in events {
            insert_on(&tx, e)?;
        }
        tx.commit()?;
        Ok(events.len())
    }

    /// The most recent events, newest first (for the UI timeline).
    pub fn recent_events(&self, limit: u32) -> Result<Vec<Event>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT ts, pid, data FROM events ORDER BY ts DESC, id DESC LIMIT ?1")?;
        let rows = stmt
            .query_map([limit], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, u32>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(|(ts, pid, data)| {
                Ok(Event {
                    ts,
                    pid,
                    kind: from_json(&data)?,
                })
            })
            .collect()
    }

    /// Events for `pid` at or after `since_ms`, oldest first.
    pub fn events_for_pid(&self, pid: u32, since_ms: i64) -> Result<Vec<Event>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT ts, data FROM events WHERE pid = ?1 AND ts >= ?2 ORDER BY ts, id")?;
        let rows = stmt
            .query_map(params![pid, since_ms], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(|(ts, data)| {
                Ok(Event {
                    ts,
                    pid,
                    kind: from_json(&data)?,
                })
            })
            .collect()
    }

    /// Most recent domain whose DNS answer was `ip`, at or before `at_ms`.
    /// Backs `dns_before` / domain attribution after a restart, before the
    /// in-memory DNS cache is warm.
    pub fn domain_for_ip(&self, ip: &str, at_ms: i64) -> Result<Option<String>, StoreError> {
        use rusqlite::OptionalExtension;
        Ok(self
            .conn
            .query_row(
                "SELECT name FROM dns WHERE answer = ?1 AND ts <= ?2 ORDER BY ts DESC, id DESC LIMIT 1",
                params![ip, at_ms],
                |r| r.get(0),
            )
            .optional()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::event::fixtures::all_kinds;

    #[test]
    fn every_kind_round_trips() {
        let s = Store::open_in_memory().unwrap();
        let evs = all_kinds(1_000, 5);
        for e in &evs {
            s.insert_event(e).unwrap();
        }
        assert_eq!(s.events_for_pid(5, 0).unwrap(), evs);
        assert!(s.events_for_pid(5, 1_001).unwrap().is_empty());
        assert!(s.events_for_pid(6, 0).unwrap().is_empty());
    }

    #[test]
    fn net_and_dns_populate_derived_tables() {
        let s = Store::open_in_memory().unwrap();
        for e in all_kinds(1_000, 5) {
            s.insert_event(&e).unwrap();
        }
        assert_eq!(s.row_count("connections").unwrap(), 1);
        // The fixture DnsQuery has two answers.
        assert_eq!(s.row_count("dns").unwrap(), 2);
        assert_eq!(
            s.domain_for_ip("203.0.113.7", 1_000).unwrap().as_deref(),
            Some("example.com")
        );
        assert_eq!(
            s.domain_for_ip("2001:db8::1", 2_000).unwrap().as_deref(),
            Some("example.com")
        );
        assert_eq!(s.domain_for_ip("203.0.113.7", 999).unwrap(), None);
    }

    #[test]
    fn batch_insert_is_equivalent_to_single_inserts() {
        let s = Store::open_in_memory().unwrap();
        let evs = all_kinds(1_000, 5);
        assert_eq!(s.insert_events(&evs).unwrap(), evs.len());
        assert_eq!(s.events_for_pid(5, 0).unwrap(), evs);
        assert_eq!(s.row_count("connections").unwrap(), 1);
        assert_eq!(s.row_count("dns").unwrap(), 2);
        assert_eq!(s.insert_events(&[]).unwrap(), 0);
    }

    #[test]
    fn recent_events_newest_first() {
        let s = Store::open_in_memory().unwrap();
        for e in all_kinds(1_000, 5) {
            s.insert_event(&e).unwrap();
        }
        s.insert_event(&Event {
            ts: 2_000,
            pid: 6,
            kind: EventKind::ProcessExit,
        })
        .unwrap();
        let r = s.recent_events(3).unwrap();
        assert_eq!(r.len(), 3);
        assert_eq!(r[0].pid, 6);
    }

    #[test]
    fn dns_without_answers_records_one_row() {
        let s = Store::open_in_memory().unwrap();
        s.insert_event(&Event {
            ts: 1,
            pid: 1,
            kind: EventKind::DnsQuery {
                name: "nx.example".into(),
                answers: vec![],
            },
        })
        .unwrap();
        assert_eq!(s.row_count("dns").unwrap(), 1);
    }

    #[test]
    fn prune_removes_old_rows_from_all_three_tables() {
        let s = Store::open_in_memory().unwrap();
        for e in all_kinds(1_000, 5) {
            s.insert_event(&e).unwrap();
        }
        for e in all_kinds(9_000, 5) {
            s.insert_event(&e).unwrap();
        }
        let n_kinds = all_kinds(0, 0).len();
        assert_eq!(s.prune_events(5_000).unwrap(), n_kinds);
        assert_eq!(s.row_count("events").unwrap(), n_kinds as i64);
        assert_eq!(s.row_count("connections").unwrap(), 1);
        assert_eq!(s.row_count("dns").unwrap(), 2);
        assert!(
            s.events_for_pid(5, 0)
                .unwrap()
                .iter()
                .all(|e| e.ts == 9_000)
        );
    }
}
