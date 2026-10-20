//! Bounded raw history. Alerts contain their own process/evidence snapshots and
//! are deliberately independent of raw timeline retention.

use rusqlite::params;

use super::{Store, StoreError};

#[derive(Debug, Default, PartialEq, Eq)]
pub struct HistoryPruned {
    pub events: usize,
    pub exited_processes: usize,
}

impl Store {
    /// Keep the newest raw events by (timestamp, id), plus a bounded history of
    /// exited processes. Live process identities, alerts, decisions, feedback,
    /// profiles, trust and quarantine records are never removed by this method.
    /// Row limits bound history volume, not the size of the entire database.
    pub fn maintain_history(
        &self,
        older_than_ms: i64,
        max_events: u32,
        max_exited_processes: u32,
    ) -> Result<HistoryPruned, StoreError> {
        if max_events == 0 || max_exited_processes == 0 {
            return Err(StoreError::Corrupt {
                column: "history limits",
                value: "limits must be positive".into(),
            });
        }
        let tx = self.conn.unchecked_transaction()?;
        let expired = tx.execute("DELETE FROM events WHERE ts < ?1", [older_than_ms])?;
        // The timestamp index also orders rowids. Unlike DELETE/OFFSET over the
        // entire old tail, this only scans the retained prefix to find a cutoff.
        let excess = tx.execute(
            "DELETE FROM events WHERE (ts, id) < (
                 SELECT ts, id FROM events ORDER BY ts DESC, id DESC LIMIT 1 OFFSET ?1
             )",
            [max_events - 1],
        )?;
        let exited_processes = tx.execute(
            "DELETE FROM processes WHERE exit_time IS NOT NULL AND (
                 exit_time < ?1 OR id IN (
                     SELECT id FROM processes WHERE exit_time IS NOT NULL
                     ORDER BY exit_time DESC, id DESC LIMIT -1 OFFSET ?2
                 )
             )",
            params![older_than_ms, max_exited_processes],
        )?;
        tx.commit()?;
        // Reclaim only a small amount of free space per maintenance cycle. This
        // is a no-op for older databases until they are compacted offline.
        self.conn.execute_batch("PRAGMA incremental_vacuum(256);")?;
        Ok(HistoryPruned {
            events: expired + excess,
            exited_processes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Action, Event, EventKind, Verdict, VerdictLabel};

    #[test]
    fn bounded_history_preserves_alert_evidence_and_cascades_network_rows() {
        let store = Store::open_in_memory().unwrap();
        // Deliberately out of timestamp order, including ties at the cutoff.
        for ts in [40, 10, 30, 40, 20, 40] {
            store
                .insert_event(&Event {
                    ts,
                    pid: 7,
                    kind: EventKind::DnsQuery {
                        name: "fixture.example".into(),
                        answers: vec!["192.0.2.1".parse().unwrap()],
                    },
                })
                .unwrap();
        }
        let id = store
            .insert_alert(
                10,
                7,
                "fixture",
                &Verdict {
                    label: VerdictLabel::Suspicious,
                    p: [0., 1., 0.],
                    tactic: "none".into(),
                    severity: 2.,
                    action: Action::AskUser,
                    tier: 0,
                    reasons: vec!["preserve this evidence".into()],
                },
            )
            .unwrap();
        store.conn.execute("INSERT INTO feedback (alert_id,ts,user_action,note) VALUES (?1,11,'allow','reviewed')", [id]).unwrap();
        let result = store.maintain_history(15, 2, 10).unwrap();
        assert_eq!(result.events, 4);
        assert_eq!(store.row_count("events").unwrap(), 2);
        assert_eq!(store.row_count("dns").unwrap(), 2);
        assert_eq!(store.row_count("alerts").unwrap(), 1);
        assert_eq!(store.row_count("feedback").unwrap(), 1);
        let retained: Vec<i64> = store
            .conn
            .prepare("SELECT id FROM events ORDER BY id")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(retained, [4, 6]);
        assert_eq!(
            store.maintain_history(15, 2, 10).unwrap(),
            HistoryPruned::default()
        );
        assert!(store.maintain_history(0, 0, 10).is_err());
        assert_eq!(store.row_count("events").unwrap(), 2);
    }

    #[test]
    fn exited_history_is_bounded_but_live_processes_survive() {
        let store = Store::open_in_memory().unwrap();
        for (pid, exit) in [(1, Some(10)), (2, None), (3, Some(30)), (4, Some(20))] {
            store.conn.execute(
                "INSERT INTO processes (pid,ppid,start_time,exit_time,exe_sha256,exe_path,path_class,tainted,app_id)
                 VALUES (?1,0,1,?2,'fixture','fixture','other',0,'fixture')",
                params![pid, exit],
            ).unwrap();
        }
        assert_eq!(
            store.maintain_history(0, 10, 1).unwrap().exited_processes,
            2
        );
        assert_eq!(store.row_count("processes").unwrap(), 2);
        assert_eq!(
            store.maintain_history(40, 10, 1).unwrap().exited_processes,
            1
        );
        assert_eq!(store.row_count("processes").unwrap(), 1);
        let pid: u32 = store
            .conn
            .query_row("SELECT pid FROM processes", [], |r| r.get(0))
            .unwrap();
        assert_eq!(pid, 2);
    }
}
