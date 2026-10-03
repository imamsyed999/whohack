use std::net::IpAddr;

use serde::{Deserialize, Serialize};

/// Transport protocol of a network flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    pub const fn as_str(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        }
    }
}

/// Class of a sensitive file, resolved by the collector from the per-OS path
/// table in config (SPEC §9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensitiveClass {
    /// Chrome/Edge/Brave `Login Data`, Firefox `logins.json` / `key4.db`.
    BrowserPasswords,
    /// macOS Keychain databases.
    Keychain,
    /// `~/.ssh` contents.
    SshKeys,
    CryptoWallet,
    /// LSASS process memory (Windows).
    Lsass,
    /// User documents (benign by default; feeds `file:read_documents`).
    Documents,
    /// A persistence location written as a plain file (cron dir, LaunchAgents, ...).
    PersistenceLocation,
    Other,
}

/// Persistence mechanism; one variant per `persistence:*` capability tag (SPEC §9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PersistenceKind {
    // Windows
    RunKey,
    StartupFolder,
    ScheduledTask,
    Service,
    // macOS
    LaunchAgent,
    LoginItem,
    // Linux
    Cron,
    SystemdUnit,
    ShellRc,
    /// XDG autostart entry (`~/.config/autostart/*.desktop`). Extension of
    /// SPEC §9, which has no Linux desktop-session autostart tag.
    Autostart,
}

impl PersistenceKind {
    pub const ALL: [PersistenceKind; 10] = [
        PersistenceKind::RunKey,
        PersistenceKind::StartupFolder,
        PersistenceKind::ScheduledTask,
        PersistenceKind::Service,
        PersistenceKind::LaunchAgent,
        PersistenceKind::LoginItem,
        PersistenceKind::Cron,
        PersistenceKind::SystemdUnit,
        PersistenceKind::ShellRc,
        PersistenceKind::Autostart,
    ];

    /// Snake-case name, identical to the serde form and the tag suffix.
    pub const fn as_str(self) -> &'static str {
        match self {
            PersistenceKind::RunKey => "run_key",
            PersistenceKind::StartupFolder => "startup_folder",
            PersistenceKind::ScheduledTask => "scheduled_task",
            PersistenceKind::Service => "service",
            PersistenceKind::LaunchAgent => "launch_agent",
            PersistenceKind::LoginItem => "login_item",
            PersistenceKind::Cron => "cron",
            PersistenceKind::SystemdUnit => "systemd_unit",
            PersistenceKind::ShellRc => "shell_rc",
            PersistenceKind::Autostart => "autostart",
        }
    }

    pub fn parse(s: &str) -> Option<PersistenceKind> {
        PersistenceKind::ALL.into_iter().find(|k| k.as_str() == s)
    }
}

impl SensitiveClass {
    pub const ALL: [SensitiveClass; 8] = [
        SensitiveClass::BrowserPasswords,
        SensitiveClass::Keychain,
        SensitiveClass::SshKeys,
        SensitiveClass::CryptoWallet,
        SensitiveClass::Lsass,
        SensitiveClass::Documents,
        SensitiveClass::PersistenceLocation,
        SensitiveClass::Other,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            SensitiveClass::BrowserPasswords => "browser_passwords",
            SensitiveClass::Keychain => "keychain",
            SensitiveClass::SshKeys => "ssh_keys",
            SensitiveClass::CryptoWallet => "crypto_wallet",
            SensitiveClass::Lsass => "lsass",
            SensitiveClass::Documents => "documents",
            SensitiveClass::PersistenceLocation => "persistence_location",
            SensitiveClass::Other => "other",
        }
    }

    pub fn parse(s: &str) -> Option<SensitiveClass> {
        SensitiveClass::ALL.into_iter().find(|k| k.as_str() == s)
    }
}

/// What a process did. Produced by collectors, normalized, then tagged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EventKind {
    /// A process started (or, at collector startup, was already running; then
    /// `Event::ts` is its real start time).
    ///
    /// Extension of SPEC §7, which declares `ProcessStart` without fields:
    /// collectors are the only source of this data and taint/lineage needs it.
    /// `cmdline` feeds Tier 0 rules and the tagger only; it is NEVER placed in
    /// the decision-model state (SPEC §12.3).
    ProcessStart {
        ppid: u32,
        /// Full executable path when known, otherwise the best available name.
        exe: String,
        cmdline: Option<String>,
    },
    ProcessExit,
    NetConnect {
        remote_ip: IpAddr,
        remote_port: u16,
        proto: Proto,
        domain: Option<String>,
        /// True if a DNS answer for `remote_ip` was seen before the connect.
        dns_before: bool,
    },
    DnsQuery {
        name: String,
        answers: Vec<IpAddr>,
    },
    FileAccess {
        path: String,
        class: SensitiveClass,
        write: bool,
    },
    Persistence {
        location: PersistenceKind,
        target: String,
    },
    Injection {
        target_pid: u32,
    },
    /// Ransomware signal: many files modified/renamed in a short window.
    FileBurst {
        modified: u32,
        renamed: u32,
        window_ms: u32,
    },
}

impl EventKind {
    /// Discriminant name; identical to the serde `type` tag. Stored in the
    /// `events.kind` column for indexed filtering.
    pub const fn name(&self) -> &'static str {
        match self {
            EventKind::ProcessStart { .. } => "process_start",
            EventKind::ProcessExit => "process_exit",
            EventKind::NetConnect { .. } => "net_connect",
            EventKind::DnsQuery { .. } => "dns_query",
            EventKind::FileAccess { .. } => "file_access",
            EventKind::Persistence { .. } => "persistence",
            EventKind::Injection { .. } => "injection",
            EventKind::FileBurst { .. } => "file_burst",
        }
    }
}

/// One normalized event attributed to a process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// Unix ms.
    pub ts: i64,
    pub pid: u32,
    pub kind: EventKind,
}

#[cfg(test)]
pub(crate) mod fixtures {
    use super::*;

    /// One event of every kind, for round-trip and store tests.
    pub fn all_kinds(ts: i64, pid: u32) -> Vec<Event> {
        let kinds = vec![
            EventKind::ProcessStart {
                ppid: 1,
                exe: "/home/u/Downloads/tool".into(),
                cmdline: Some("tool --flag \"quoted arg\"".into()),
            },
            EventKind::ProcessExit,
            EventKind::NetConnect {
                remote_ip: "203.0.113.7".parse().unwrap(),
                remote_port: 443,
                proto: Proto::Tcp,
                domain: Some("example.com".into()),
                dns_before: true,
            },
            EventKind::DnsQuery {
                name: "example.com".into(),
                answers: vec![
                    "203.0.113.7".parse().unwrap(),
                    "2001:db8::1".parse().unwrap(),
                ],
            },
            EventKind::FileAccess {
                path: "/home/u/.ssh/id_ed25519".into(),
                class: SensitiveClass::SshKeys,
                write: false,
            },
            EventKind::Persistence {
                location: PersistenceKind::Cron,
                target: "/var/spool/cron/u".into(),
            },
            EventKind::Injection { target_pid: 1234 },
            EventKind::FileBurst {
                modified: 500,
                renamed: 480,
                window_ms: 10_000,
            },
        ];
        kinds
            .into_iter()
            .map(|kind| Event { ts, pid, kind })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::all_kinds;
    use super::*;

    #[test]
    fn every_kind_round_trips_and_tag_matches_name() {
        for e in all_kinds(1_700_000_000_000, 99) {
            let v = serde_json::to_value(&e).unwrap();
            assert_eq!(v["kind"]["type"], e.kind.name());
            let back: Event = serde_json::from_value(v).unwrap();
            assert_eq!(back, e);
        }
    }

    #[test]
    fn enum_string_forms_match_serde() {
        for k in PersistenceKind::ALL {
            assert_eq!(
                serde_json::to_string(&k).unwrap(),
                format!("\"{}\"", k.as_str())
            );
            assert_eq!(PersistenceKind::parse(k.as_str()), Some(k));
        }
        for c in SensitiveClass::ALL {
            assert_eq!(
                serde_json::to_string(&c).unwrap(),
                format!("\"{}\"", c.as_str())
            );
            assert_eq!(SensitiveClass::parse(c.as_str()), Some(c));
        }
    }

    #[test]
    fn net_connect_shape() {
        let e = Event {
            ts: 1,
            pid: 2,
            kind: EventKind::NetConnect {
                remote_ip: "198.51.100.1".parse().unwrap(),
                remote_port: 8080,
                proto: Proto::Udp,
                domain: None,
                dns_before: false,
            },
        };
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(v["kind"]["remote_ip"], "198.51.100.1");
        assert_eq!(v["kind"]["proto"], "udp");
        assert!(v["kind"]["domain"].is_null());
    }
}
