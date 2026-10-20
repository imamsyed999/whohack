use std::num::NonZeroUsize;

use lru::LruCache;
use whohack_core::config::SensitiveConfig;
use whohack_core::{CapabilityTag, EventKind, Observation, Os, PathClass, SensitiveClass};

use crate::net::NetworkTags;
use crate::sensitive::SensitivePaths;

#[derive(Debug)]
pub struct Tagger {
    net: NetworkTags,
    paths: SensitivePaths,
    names: LruCache<u32, (i64, String)>,
}

fn binary(path: &str) -> String {
    path.rsplit(['/', '\\'])
        .next()
        .unwrap_or(path)
        .to_ascii_lowercase()
        .trim_end_matches(".exe")
        .to_string()
}

fn interpreter(name: &str) -> bool {
    matches!(
        name,
        "powershell"
            | "pwsh"
            | "cmd"
            | "wscript"
            | "cscript"
            | "mshta"
            | "bash"
            | "sh"
            | "dash"
            | "zsh"
            | "fish"
            | "python"
            | "python3"
            | "osascript"
    ) || name
        .strip_prefix("python3.")
        .is_some_and(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
}

impl Tagger {
    pub fn new(dns_visible: bool, os: Os, cfg: &SensitiveConfig) -> Self {
        Self {
            net: NetworkTags::new(dns_visible),
            paths: SensitivePaths::new(os, cfg),
            names: LruCache::new(NonZeroUsize::new(16_384).unwrap()),
        }
    }

    pub fn tag(&mut self, obs: &mut Observation) {
        self.net.tag(obs);
        let mut add = |s| obs.tags.push(CapabilityTag::from_static(s));
        match &obs.event.kind {
            EventKind::ProcessStart { ppid, exe, cmdline } => {
                let name = binary(exe);
                if interpreter(&name) {
                    add("exec:script_interpreter");
                }
                if matches!(
                    name.as_str(),
                    "rundll32" | "regsvr32" | "certutil" | "bitsadmin"
                ) || (matches!(name.as_str(), "curl" | "wget")
                    && self
                        .names
                        .get(ppid)
                        .is_some_and(|(_, parent)| !interpreter(parent)))
                {
                    add("exec:lolbin");
                }
                if matches!(name.as_str(), "powershell" | "pwsh") {
                    let args: Vec<_> = cmdline
                        .as_deref()
                        .unwrap_or("")
                        .split_ascii_whitespace()
                        .map(|a| a.trim_matches(['\'', '"']).to_ascii_lowercase())
                        .collect();
                    if args
                        .windows(2)
                        .any(|a| matches!(a[0].as_str(), "-windowstyle" | "-w") && a[1] == "hidden")
                    {
                        add("exec:hidden_window");
                    }
                }
                if *ppid != 0
                    && obs.process.as_ref().is_some_and(|p| {
                        matches!(p.path_class, PathClass::Downloads | PathClass::Temp)
                    })
                {
                    add("exec:child_from_downloads_or_temp");
                }
                self.names.put(
                    obs.event.pid,
                    (
                        obs.process.as_ref().map_or(obs.event.ts, |p| p.start_time),
                        name,
                    ),
                );
            }
            EventKind::ProcessExit => {
                if let Some(p) = &obs.process
                    && self
                        .names
                        .peek(&p.pid)
                        .is_some_and(|(start, _)| *start == p.start_time)
                {
                    self.names.pop(&p.pid);
                }
            }
            EventKind::FileAccess { path, class, write } => {
                let class = if *class == SensitiveClass::Other {
                    self.paths.class(path)
                } else {
                    *class
                };
                let tag = match class {
                    SensitiveClass::BrowserPasswords => Some("credential_access:browser_passwords"),
                    SensitiveClass::Keychain => Some("credential_access:keychain"),
                    SensitiveClass::SshKeys => Some("credential_access:ssh_keys"),
                    SensitiveClass::CryptoWallet => Some("credential_access:crypto_wallets"),
                    SensitiveClass::Lsass => Some("credential_access:lsass"),
                    SensitiveClass::Documents if !write => Some("file:read_documents"),
                    _ => None,
                };
                if let Some(tag) = tag {
                    add(tag);
                }
                if *write && let Some(kind) = self.paths.persistence(path) {
                    obs.tags
                        .push(format!("persistence:{}", kind.as_str()).into());
                }
            }
            EventKind::Persistence { location, .. } => obs
                .tags
                .push(format!("persistence:{}", location.as_str()).into()),
            EventKind::Injection { .. } => add("injection:remote_thread"),
            EventKind::FileBurst {
                modified,
                renamed,
                window_ms,
            } => {
                if *window_ms > 0
                    && *window_ms <= 60_000
                    && modified.saturating_add(*renamed) >= 100
                {
                    add("impact:mass_file_modification");
                }
            }
            EventKind::NetConnect { .. }
            | EventKind::DnsQuery { .. }
            | EventKind::NetStats { .. } => {}
        }
        obs.tags.sort();
        obs.tags.dedup();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use whohack_core::Event;
    #[test]
    fn file_persistence_and_burst_require_evidence() {
        let mut t = Tagger::new(false, Os::Linux, &SensitiveConfig::default());
        let mut obs = Observation::bare(Event {
            ts: 0,
            pid: 7,
            kind: EventKind::FileAccess {
                path: "/home/u/.ssh/id_ed25519".into(),
                class: SensitiveClass::Other,
                write: false,
            },
        });
        t.tag(&mut obs);
        assert_eq!(
            obs.tags,
            [CapabilityTag::from_static("credential_access:ssh_keys")]
        );
        t.tag(&mut obs);
        assert_eq!(obs.tags.len(), 1);
        for (count, expected) in [(1, false), (100, true)] {
            let mut o = Observation::bare(Event {
                ts: 0,
                pid: 7,
                kind: EventKind::FileBurst {
                    modified: count,
                    renamed: 0,
                    window_ms: 1_000,
                },
            });
            t.tag(&mut o);
            assert_eq!(!o.tags.is_empty(), expected);
        }
    }
    #[test]
    fn hidden_switch_is_only_interpreted_for_powershell() {
        let mut t = Tagger::new(false, Os::Windows, &SensitiveConfig::default());
        for (exe, hidden) in [("powershell.exe", true), ("pdf.exe", false)] {
            let mut o = Observation::bare(Event {
                ts: 0,
                pid: 7,
                kind: EventKind::ProcessStart {
                    ppid: 1,
                    exe: exe.into(),
                    cmdline: Some(format!("{exe} -WindowStyle Hidden")),
                },
            });
            t.tag(&mut o);
            assert_eq!(
                o.tags.iter().any(|t| t.as_str() == "exec:hidden_window"),
                hidden
            );
        }
    }
}
