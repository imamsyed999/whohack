//! Presentation of download associations. Never used to authorize a response.

use whohack_core::ProcessInfo;
use whohack_ipc::DownloadFileSummary;

// Full evidence remains in the store. Bound strings to fit IPC frames.
pub fn display_text(value: &str) -> String {
    let mut chars = value.chars();
    let mut text: String = chars.by_ref().take(256).collect();
    if chars.next().is_some() {
        text.push('…');
    }
    text
}

pub fn files(p: &ProcessInfo) -> Vec<DownloadFileSummary> {
    let mut files = Vec::new();
    for (file, evidence) in [(Some(&p.exe), "executed"), (p.script.as_ref(), "script")] {
        if let Some(file) = file.filter(|f| f.origin.is_downloaded()) {
            files.push(DownloadFileSummary {
                path: display_text(&file.path),
                evidence: evidence.into(),
                observed_at: p.start_time,
            });
        }
    }
    for input in p.downloaded_inputs.iter().take(8) {
        files.push(DownloadFileSummary {
            path: display_text(&input.file.path),
            evidence: if input.observed_at < p.start_time {
                "inherited"
            } else if input.read_observed {
                "observed_read"
            } else {
                "launch_argument"
            }
            .into(),
            observed_at: input.observed_at,
        });
    }
    files
}
