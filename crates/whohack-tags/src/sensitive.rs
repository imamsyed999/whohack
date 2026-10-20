//! Lexical path classification. Paths are not opened or read. Windows comparisons
//! are case insensitive; Unix comparisons preserve case and component boundaries.
use whohack_core::config::SensitiveConfig;
use whohack_core::{Os, PersistenceKind, SensitiveClass};

#[derive(Debug, Clone)]
pub struct SensitivePaths {
    os: Os,
    extra: Vec<(SensitiveClass, String)>,
    persistence: Vec<(PersistenceKind, String)>,
}

fn normalize(path: &str, os: Os) -> String {
    let path = if os == Os::Windows {
        path.replace('\\', "/").to_ascii_lowercase()
    } else {
        path.to_string()
    };
    let mut parts = Vec::new();
    for part in path.split('/') {
        match part {
            "." | "" => {}
            ".." => {
                parts.pop();
            }
            p => parts.push(p),
        }
    }
    format!("/{}", parts.join("/"))
}

pub fn within(path: &str, root: &str) -> bool {
    path == root || path.strip_prefix(root).is_some_and(|s| s.starts_with('/'))
}

impl SensitivePaths {
    pub fn new(os: Os, cfg: &SensitiveConfig) -> Self {
        let mut extra: Vec<_> = cfg
            .classes()
            .into_iter()
            .map(|(c, p)| (c, normalize(&p.to_string_lossy(), os)))
            .collect();
        let mut persistence: Vec<_> = cfg
            .persistence()
            .into_iter()
            .map(|(c, p)| (c, normalize(&p.to_string_lossy(), os)))
            .collect();
        // Most specific override wins for nested configured locations.
        extra.sort_by_key(|(_, p)| std::cmp::Reverse(p.len()));
        persistence.sort_by_key(|(_, p)| std::cmp::Reverse(p.len()));
        Self {
            os,
            extra,
            persistence,
        }
    }

    pub fn class(&self, path: &str) -> SensitiveClass {
        let p = normalize(path, self.os);
        if let Some((c, _)) = self.extra.iter().find(|(_, root)| within(&p, root)) {
            return *c;
        }
        let parts: Vec<_> = p.split('/').collect();
        let name = parts.last().copied().unwrap_or("");
        let browser = match self.os {
            Os::Windows => {
                p.contains("/appdata/")
                    && [
                        "/google/chrome/",
                        "/microsoft/edge/",
                        "/bravesoftware/",
                        "/mozilla/firefox/",
                    ]
                    .iter()
                    .any(|s| p.contains(s))
            }
            Os::Linux => [
                "/.config/google-chrome/",
                "/.config/chromium/",
                "/.config/microsoft-edge/",
                "/.config/BraveSoftware/",
                "/.mozilla/firefox/",
            ]
            .iter()
            .any(|s| p.contains(s)),
            Os::MacOs => {
                p.contains("/Library/Application Support/")
                    && [
                        "/Google/Chrome/",
                        "/Microsoft Edge/",
                        "/BraveSoftware/",
                        "/Firefox/",
                    ]
                    .iter()
                    .any(|s| p.contains(s))
            }
        };
        let browser_name = if self.os == Os::Windows {
            name == "login data"
        } else {
            name == "Login Data"
        };
        if browser && (browser_name || matches!(name, "logins.json" | "key4.db")) {
            return SensitiveClass::BrowserPasswords;
        }
        if parts.contains(&".ssh") {
            return SensitiveClass::SshKeys;
        }
        if self.os == Os::MacOs && (p.contains("/Library/Keychains/") || p == "/Library/Keychains")
        {
            return SensitiveClass::Keychain;
        }
        if parts
            .iter()
            .any(|x| matches!(*x, ".bitcoin" | ".electrum" | ".ethereum"))
            || [
                "/AppData/Roaming/Bitcoin/",
                "/AppData/Roaming/Electrum/",
                "/Library/Application Support/Bitcoin/",
                "/Library/Application Support/Electrum/",
            ]
            .iter()
            .any(|s| {
                if self.os == Os::Windows {
                    p.contains(&s.to_ascii_lowercase())
                } else {
                    p.contains(s)
                }
            })
        {
            return SensitiveClass::CryptoWallet;
        }
        if self.persistence(path).is_some() {
            return SensitiveClass::PersistenceLocation;
        }
        if parts.contains(&if self.os == Os::Windows {
            "documents"
        } else {
            "Documents"
        }) {
            return SensitiveClass::Documents;
        }
        SensitiveClass::Other
    }

    pub fn persistence(&self, path: &str) -> Option<PersistenceKind> {
        use PersistenceKind::*;
        let p = normalize(path, self.os);
        if let Some((k, _)) = self.persistence.iter().find(|(_, root)| within(&p, root)) {
            return Some(*k);
        }
        match self.os {
            Os::Linux => {
                if [
                    "/etc/crontab",
                    "/etc/cron.d",
                    "/etc/cron.daily",
                    "/etc/cron.hourly",
                    "/etc/cron.weekly",
                    "/etc/cron.monthly",
                    "/var/spool/cron",
                ]
                .iter()
                .any(|r| within(&p, r))
                {
                    return Some(Cron);
                }
                if within(&p, "/etc/systemd/system")
                    || within(&p, "/usr/lib/systemd/system")
                    || p.contains("/.config/systemd/user/")
                {
                    return Some(SystemdUnit);
                }
                if p.contains("/.config/autostart/") || within(&p, "/etc/xdg/autostart") {
                    return Some(Autostart);
                }
                if [
                    "/.bashrc",
                    "/.bash_profile",
                    "/.profile",
                    "/.zshrc",
                    "/.zprofile",
                ]
                .iter()
                .any(|s| p.ends_with(s))
                    || within(&p, "/etc/profile.d")
                    || p == "/etc/profile"
                {
                    return Some(ShellRc);
                }
            }
            Os::MacOs => {
                if p.contains("/Library/LaunchAgents/") || p.contains("/Library/LaunchDaemons/") {
                    return Some(LaunchAgent);
                }
            }
            Os::Windows => {
                if p.contains("/start menu/programs/startup/") {
                    return Some(StartupFolder);
                }
                if p.contains("/windows/system32/tasks/") {
                    return Some(ScheduledTask);
                }
                if p.contains("/software/microsoft/windows/currentversion/run/")
                    || p.ends_with("/software/microsoft/windows/currentversion/run")
                    || p.contains("/software/microsoft/windows/currentversion/runonce/")
                    || p.ends_with("/software/microsoft/windows/currentversion/runonce")
                {
                    return Some(RunKey);
                }
                // The 32-bit registry view has an extra Wow6432Node component.
                if p.contains("/software/wow6432node/microsoft/windows/currentversion/run/")
                    || p.ends_with("/software/wow6432node/microsoft/windows/currentversion/run")
                    || p.contains("/software/wow6432node/microsoft/windows/currentversion/runonce/")
                    || p.ends_with("/software/wow6432node/microsoft/windows/currentversion/runonce")
                {
                    return Some(RunKey);
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn per_os_paths_and_boundary_checks() {
        let cases = [
            (
                Os::Linux,
                "/home/u/.config/google-chrome/Default/Login Data",
            ),
            (
                Os::Windows,
                r"C:\Users\U\AppData\Local\Google\Chrome\User Data\Default\LOGIN DATA",
            ),
            (
                Os::MacOs,
                "/Users/u/Library/Application Support/Firefox/Profiles/x/logins.json",
            ),
        ];
        for (os, path) in cases {
            assert_eq!(
                SensitivePaths::new(os, &SensitiveConfig::default()).class(path),
                SensitiveClass::BrowserPasswords
            );
        }
        let c = SensitivePaths::new(Os::Linux, &SensitiveConfig::default());
        assert_eq!(c.class("/tmp/Login Data"), SensitiveClass::Other);
        assert_eq!(c.class("/home/u/.ssh/id_ed25519"), SensitiveClass::SshKeys);
        assert_eq!(c.class("/home/u/.ssh-backup/a"), SensitiveClass::Other);
        assert_eq!(c.class("/home/u/.ssh/../a"), SensitiveClass::Other);
        assert_eq!(
            c.persistence("/home/u/.config/autostart/a.desktop"),
            Some(PersistenceKind::Autostart)
        );
        assert_eq!(c.persistence("/etc/cron.daily-backup/x"), None);
        assert_eq!(
            c.persistence("/etc/systemd/system/a.service"),
            Some(PersistenceKind::SystemdUnit)
        );
    }
    #[test]
    fn configured_locations_have_component_boundaries() {
        let mut cfg = SensitiveConfig::default();
        cfg.extra_paths.insert(
            "browser_passwords".into(),
            vec!["/tmp/test/passwords".into()],
        );
        cfg.extra_persistence
            .insert("autostart".into(), vec!["/tmp/test/startup".into()]);
        let c = SensitivePaths::new(Os::Linux, &cfg);
        assert_eq!(
            c.class("/tmp/test/passwords/data"),
            SensitiveClass::BrowserPasswords
        );
        assert_eq!(
            c.class("/tmp/test/passwords-other/data"),
            SensitiveClass::Other
        );
        assert_eq!(
            c.persistence("/tmp/test/startup/entry"),
            Some(PersistenceKind::Autostart)
        );
    }
}
