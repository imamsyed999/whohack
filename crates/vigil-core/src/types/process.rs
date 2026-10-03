use serde::{Deserialize, Serialize};

use super::{FileInfo, PathClass};

/// A running (or recently exited) process and its taint state.
///
/// PIDs are reused by every OS, so a process is identified by `(pid, start_time)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    /// Unix ms.
    pub start_time: i64,
    pub exe: FileInfo,
    /// For interpreters (shells, PowerShell, wscript, python, ...): the script
    /// file being run. Extension of SPEC §7: a downloaded script taints the
    /// interpreter running it, and it is the script, not the interpreter,
    /// that identifies the "app" (`app_id`).
    #[serde(default)]
    pub script: Option<FileInfo>,
    pub path_class: PathClass,
    /// True if this process, or an ancestor, was started from a downloaded file.
    pub tainted: bool,
    /// PID of the downloaded process that tainted this lineage.
    pub taint_root: Option<u32>,
    /// Stable application identity: signing id when trusted-signed, otherwise sha256 hex.
    pub app_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Origin, SignState};

    #[test]
    fn round_trip() {
        let p = ProcessInfo {
            pid: 4242,
            ppid: 1,
            start_time: 1_700_000_000_123,
            exe: FileInfo {
                path: "/home/u/Downloads/tool".into(),
                sha256: [7; 32],
                origin: Origin::Downloaded {
                    url: None,
                    referrer: None,
                },
                sign: SignState::Unsigned,
                yara_hits: vec![],
                first_seen: 1_700_000_000_000,
            },
            script: None,
            path_class: PathClass::Downloads,
            tainted: true,
            taint_root: Some(4242),
            app_id: crate::hex::encode(&[7; 32]),
        };
        let s = serde_json::to_string(&p).unwrap();
        assert_eq!(serde_json::from_str::<ProcessInfo>(&s).unwrap(), p);
        // Older records without `script` still deserialize.
        let mut v: serde_json::Value = serde_json::from_str(&s).unwrap();
        v.as_object_mut().unwrap().remove("script");
        assert_eq!(
            serde_json::from_value::<ProcessInfo>(v).unwrap().script,
            None
        );
    }
}
