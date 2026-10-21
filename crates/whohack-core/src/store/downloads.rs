//! Bounded download activity for the UI. Associations are not safety verdicts.

use rusqlite::params;

use super::{Store, StoreError};
use crate::{Event, ProcessInfo};

#[derive(Debug)]
pub struct DownloadActivity {
    pub process: ProcessInfo,
    pub exit_time: Option<i64>,
    pub events: Vec<Event>,
}

impl Store {
    /// Recent download-associated processes, including already-running readers.
    /// A missing exit record is not proof that a process is still running.
    pub fn recent_download_activity(
        &self,
        limit: u32,
    ) -> Result<Vec<DownloadActivity>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT pid, start_time, exit_time FROM processes
             WHERE tainted = 1 OR downloaded_inputs != '[]'
             ORDER BY MAX(start_time, COALESCE(
                 (SELECT MAX(json_extract(value, '$.observed_at'))
                  FROM json_each(downloaded_inputs)), start_time)) DESC, id DESC
             LIMIT ?1",
        )?;
        let ids = stmt
            .query_map([limit.min(20)], |r| {
                Ok((
                    r.get::<_, u32>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, Option<i64>>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let mut activity = Vec::new();
        for (pid, start, exit) in ids {
            let Some(process) = self.process(pid, start)? else {
                continue;
            };
            // Do not attach earlier viewer traffic to a newly opened input.
            let since = process
                .downloaded_inputs
                .iter()
                .map(|f| f.observed_at)
                .min()
                .unwrap_or(start)
                .max(start);
            let next_birth: Option<i64> = self.conn.query_row(
                "SELECT MIN(start_time) FROM processes WHERE pid = ?1 AND start_time > ?2",
                params![pid, start],
                |r| r.get(0),
            )?;
            let mut stmt = self.conn.prepare(
                "SELECT ts, data FROM events WHERE pid = ?1 AND ts >= ?2
                 AND ts <= ?3 AND ts < ?4
                 AND kind IN ('net_connect', 'dns_query', 'persistence', 'injection',
                              'file_burst', 'process_exit')
                 ORDER BY ts DESC, id DESC LIMIT 12",
            )?;
            let events = stmt
                .query_map(
                    params![
                        pid,
                        since,
                        exit.unwrap_or(i64::MAX),
                        next_birth.unwrap_or(i64::MAX)
                    ],
                    |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)),
                )?
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .map(|(ts, data)| {
                    Ok(Event {
                        ts,
                        pid,
                        kind: serde_json::from_str(&data)?,
                    })
                })
                .collect::<Result<Vec<_>, StoreError>>()?;
            activity.push(DownloadActivity {
                process,
                exit_time: exit,
                events,
            });
        }
        Ok(activity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DownloadedInput, EventKind, FileInfo, Origin, PathClass, SignState};

    fn process(pid: u32, start: i64) -> ProcessInfo {
        ProcessInfo {
            pid,
            ppid: 1,
            start_time: start,
            exe: FileInfo {
                path: "/apps/player.exe".into(),
                sha256: [1; 32],
                origin: Origin::Installed,
                sign: SignState::Unsigned,
                yara_hits: vec![],
                first_seen: 1,
            },
            script: None,
            downloaded_inputs: vec![],
            path_class: PathClass::ProgramFiles,
            tainted: true,
            taint_root: Some(pid),
            app_id: "player".into(),
        }
    }

    #[test]
    fn download_activity_excludes_earlier_traffic_exit_and_reused_pid() {
        let s = Store::open_in_memory().unwrap();
        let mut p = process(7, 100);
        p.downloaded_inputs.push(DownloadedInput {
            file: FileInfo {
                path: "/Downloads/sample.wav".into(),
                origin: Origin::Downloaded {
                    url: None,
                    referrer: None,
                },
                ..p.exe.clone()
            },
            observed_at: 200,
            read_observed: true,
        });
        s.insert_process(&p).unwrap();
        let mut next = process(7, 400);
        next.tainted = false;
        s.insert_process(&next).unwrap();
        for ts in [150, 200, 300, 400, 500] {
            s.insert_event(&Event {
                ts,
                pid: 7,
                kind: EventKind::DnsQuery {
                    name: format!("{ts}.example"),
                    answers: vec![],
                },
            })
            .unwrap();
        }
        let rows = s.recent_download_activity(20).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].events.iter().map(|e| e.ts).collect::<Vec<_>>(),
            [300, 200]
        );
        assert!(rows[0].process.downloaded_inputs[0].read_observed);
        s.mark_process_exit(7, 100, 250).unwrap();
        assert_eq!(s.recent_download_activity(20).unwrap()[0].events.len(), 1);
        assert!(s.recent_download_activity(0).unwrap().is_empty());
    }

    #[test]
    fn recent_input_in_old_viewer_sorts_first_and_results_are_bounded() {
        let s = Store::open_in_memory().unwrap();
        for pid in 1..=30 {
            s.insert_process(&process(pid, i64::from(pid))).unwrap();
        }
        let mut old = process(1, 1);
        old.downloaded_inputs.push(DownloadedInput {
            file: old.exe.clone(),
            observed_at: 999,
            read_observed: false,
        });
        s.insert_process(&old).unwrap();
        for ts in 999..1030 {
            s.insert_event(&Event {
                ts,
                pid: 1,
                kind: EventKind::DnsQuery {
                    name: "example".into(),
                    answers: vec![],
                },
            })
            .unwrap();
        }
        let rows = s.recent_download_activity(u32::MAX).unwrap();
        assert_eq!(rows.len(), 20);
        assert_eq!(rows[0].process.pid, 1);
        assert_eq!(rows[0].events.len(), 12);
    }
}
