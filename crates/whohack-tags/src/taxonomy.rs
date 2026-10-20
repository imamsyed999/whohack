//! The complete SPEC section 9 taxonomy. Reserved tags are only emitted when
//! a collector supplies evidence; a filename alone never proves a network reputation.
#[derive(Debug, Clone, Copy)]
pub struct TagDef {
    pub tag: &'static str,
    pub severity: u8,
    pub attack: Option<&'static str>,
    pub description: &'static str,
}

pub const TAGS: &[TagDef] = &[
    TagDef {
        tag: "network:vendor_domain",
        severity: 0,
        attack: None,
        description: "contact its verified vendor domain",
    },
    TagDef {
        tag: "network:known_cdn",
        severity: 0,
        attack: None,
        description: "contact a verified content delivery network",
    },
    TagDef {
        tag: "network:first_seen_destination",
        severity: 1,
        attack: None,
        description: "contact a destination not seen in recent app history",
    },
    TagDef {
        tag: "network:raw_ip_no_dns",
        severity: 2,
        attack: None,
        description: "connect to a public IP without an observed DNS answer",
    },
    TagDef {
        tag: "network:unusual_port",
        severity: 1,
        attack: None,
        description: "connect on an uncommon destination port",
    },
    TagDef {
        tag: "network:intel_hit",
        severity: 3,
        attack: None,
        description: "contact a destination on a threat intelligence list",
    },
    TagDef {
        tag: "network:beaconing",
        severity: 3,
        attack: Some("T1071"),
        description: "repeatedly connect at regular intervals",
    },
    TagDef {
        tag: "network:large_upload",
        severity: 2,
        attack: Some("T1041"),
        description: "upload a large amount of data",
    },
    TagDef {
        tag: "exec:script_interpreter",
        severity: 2,
        attack: Some("T1059"),
        description: "run a script interpreter",
    },
    TagDef {
        tag: "exec:lolbin",
        severity: 2,
        attack: Some("T1218"),
        description: "run a system utility capable of executing or fetching code",
    },
    TagDef {
        tag: "exec:hidden_window",
        severity: 2,
        attack: None,
        description: "launch a hidden command window",
    },
    TagDef {
        tag: "exec:child_from_downloads_or_temp",
        severity: 2,
        attack: None,
        description: "execute a child from Downloads or a temporary directory",
    },
    TagDef {
        tag: "credential_access:browser_passwords",
        severity: 3,
        attack: Some("T1555.003"),
        description: "access saved browser passwords",
    },
    TagDef {
        tag: "credential_access:keychain",
        severity: 3,
        attack: Some("T1555.001"),
        description: "access keychain databases",
    },
    TagDef {
        tag: "credential_access:ssh_keys",
        severity: 3,
        attack: Some("T1552.004"),
        description: "access SSH keys",
    },
    TagDef {
        tag: "credential_access:crypto_wallets",
        severity: 3,
        attack: None,
        description: "access cryptocurrency wallet data",
    },
    TagDef {
        tag: "credential_access:lsass",
        severity: 3,
        attack: Some("T1003.001"),
        description: "access Windows authentication process memory",
    },
    TagDef {
        tag: "persistence:run_key",
        severity: 2,
        attack: Some("T1547.001"),
        description: "write a Windows Run registry key",
    },
    TagDef {
        tag: "persistence:startup_folder",
        severity: 2,
        attack: Some("T1547.001"),
        description: "write a Windows startup folder",
    },
    TagDef {
        tag: "persistence:scheduled_task",
        severity: 2,
        attack: Some("T1053.005"),
        description: "create a scheduled task",
    },
    TagDef {
        tag: "persistence:service",
        severity: 2,
        attack: Some("T1543.003"),
        description: "install a system service",
    },
    TagDef {
        tag: "persistence:launch_agent",
        severity: 2,
        attack: Some("T1543.001"),
        description: "write a macOS launch agent",
    },
    TagDef {
        tag: "persistence:login_item",
        severity: 2,
        attack: Some("T1547.015"),
        description: "create a macOS login item",
    },
    TagDef {
        tag: "persistence:cron",
        severity: 2,
        attack: Some("T1053.003"),
        description: "write a cron schedule",
    },
    TagDef {
        tag: "persistence:systemd_unit",
        severity: 2,
        attack: Some("T1543.002"),
        description: "write a systemd unit",
    },
    TagDef {
        tag: "persistence:shell_rc",
        severity: 2,
        attack: Some("T1546.004"),
        description: "modify shell startup configuration",
    },
    TagDef {
        tag: "persistence:autostart",
        severity: 2,
        attack: Some("T1547.013"),
        description: "write an XDG autostart entry",
    },
    TagDef {
        tag: "defense_evasion:av_tamper",
        severity: 3,
        attack: Some("T1562"),
        description: "tamper with antivirus protection",
    },
    TagDef {
        tag: "defense_evasion:log_clear",
        severity: 3,
        attack: Some("T1070"),
        description: "clear system logs",
    },
    TagDef {
        tag: "defense_evasion:shadow_copy_delete",
        severity: 3,
        attack: Some("T1490"),
        description: "delete recovery snapshots",
    },
    TagDef {
        tag: "discovery:process_enum",
        severity: 1,
        attack: Some("T1057"),
        description: "enumerate running processes",
    },
    TagDef {
        tag: "discovery:system_info",
        severity: 1,
        attack: Some("T1082"),
        description: "query system information",
    },
    TagDef {
        tag: "collection:screen_capture",
        severity: 2,
        attack: Some("T1113"),
        description: "capture the screen",
    },
    TagDef {
        tag: "collection:clipboard",
        severity: 1,
        attack: Some("T1115"),
        description: "read the clipboard",
    },
    TagDef {
        tag: "collection:keylogging",
        severity: 3,
        attack: Some("T1056"),
        description: "record keystrokes",
    },
    TagDef {
        tag: "impact:mass_file_modification",
        severity: 3,
        attack: Some("T1486"),
        description: "modify many files in a short period",
    },
    TagDef {
        tag: "injection:remote_thread",
        severity: 3,
        attack: Some("T1055"),
        description: "inject a thread into another process",
    },
    TagDef {
        tag: "file:read_documents",
        severity: 0,
        attack: None,
        description: "read user documents",
    },
    TagDef {
        tag: "file:write_own_dir",
        severity: 0,
        attack: None,
        description: "write within its own application directory",
    },
];

pub fn lookup(tag: &str) -> Option<&'static TagDef> {
    TAGS.iter().find(|d| d.tag == tag)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn taxonomy_matches_spec_and_has_unique_valid_entries() {
        let mut names = std::collections::HashSet::new();
        for d in TAGS {
            assert!(names.insert(d.tag), "duplicate {}", d.tag);
            assert!(d.severity <= 3);
            assert!(!d.description.is_empty());
        }
        let spec = include_str!("../taxonomy-spec.md");
        for part in spec.split('`').skip(1).step_by(2) {
            if part.contains(':') && !part.contains(' ') && !part.ends_with(':') {
                assert!(lookup(part).is_some(), "missing {part}");
            }
        }
        assert_eq!(TAGS.len(), 39); // 38 in SPEC plus XDG autostart
    }
}
