//! Service configuration (TOML).
//!
//! Missing fields take defaults; unknown fields are rejected so a typo can
//! never silently do nothing. Relative paths resolve against the directory
//! containing the config file.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::types::{Os, PersistenceKind, ResponseMode, SensitiveClass};

/// Smallest and largest accepted event retention, in days.
pub const RETENTION_DAYS_RANGE: std::ops::RangeInclusive<u32> = 1..=3650;
/// Accepted polling interval for polling collectors, in milliseconds.
pub const POLL_INTERVAL_MS_RANGE: std::ops::RangeInclusive<u64> = 100..=60_000;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read config file {path}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(transparent)]
    Parse(#[from] toml::de::Error),
    #[error(transparent)]
    Serialize(#[from] toml::ser::Error),
    #[error("invalid config value: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub mode: ResponseMode,
    pub paths: PathsConfig,
    pub storage: StorageConfig,
    pub logging: LoggingConfig,
    pub collect: CollectConfig,
    pub sensitive: SensitiveConfig,
    pub ipc: IpcConfig,
}

/// Local IPC between the service and the tray UI (SPEC §14).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IpcConfig {
    /// Unix socket path or Windows named pipe name.
    pub endpoint: String,
}

impl Default for IpcConfig {
    fn default() -> Self {
        let endpoint = match Os::current() {
            Os::Linux => "/run/vigil/vigil.sock",
            Os::MacOs => "/var/run/vigil/vigil.sock",
            Os::Windows => r"\\.\pipe\vigil",
        };
        IpcConfig {
            endpoint: endpoint.to_string(),
        }
    }
}

/// Additional sensitive locations on top of the built-in per-OS table
/// (SPEC §9). Keys are class / persistence-kind names, e.g.
/// `browser_passwords = ["/srv/profiles"]`, `autostart = ["/etc/xdg/autostart"]`.
/// A path may be a directory (covers its contents) or a single file.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SensitiveConfig {
    pub extra_paths: BTreeMap<String, Vec<PathBuf>>,
    pub extra_persistence: BTreeMap<String, Vec<PathBuf>>,
}

impl SensitiveConfig {
    /// Typed view of `extra_paths` (validated by `Config::validate`).
    pub fn classes(&self) -> Vec<(SensitiveClass, PathBuf)> {
        self.extra_paths
            .iter()
            .filter_map(|(k, v)| SensitiveClass::parse(k).map(|c| (c, v)))
            .flat_map(|(c, v)| v.iter().map(move |p| (c, p.clone())))
            .collect()
    }

    /// Typed view of `extra_persistence` (validated by `Config::validate`).
    pub fn persistence(&self) -> Vec<(PersistenceKind, PathBuf)> {
        self.extra_persistence
            .iter()
            .filter_map(|(k, v)| PersistenceKind::parse(k).map(|c| (c, v)))
            .flat_map(|(c, v)| v.iter().map(move |p| (c, p.clone())))
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PathsConfig {
    pub data_dir: PathBuf,
    pub log_dir: PathBuf,
    /// Detection content: `yara/*.yar`, Tier 0 rules, behavior profiles.
    pub rules_dir: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StorageConfig {
    /// Database file name, relative to `paths.data_dir`, or absolute.
    pub db_file: PathBuf,
    /// Rolling retention for `events`, `connections`, and `dns` rows.
    pub event_retention_days: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    #[default]
    Text,
    Json,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LoggingConfig {
    /// A `tracing` EnvFilter directive, e.g. `"info"` or `"info,vigil_core=debug"`.
    /// The service validates the syntax; `RUST_LOG` overrides it at runtime.
    pub level: String,
    pub format: LogFormat,
    /// Also write a daily-rolling log file in `paths.log_dir`.
    pub to_file: bool,
}

/// Which collector implementation to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectBackend {
    /// Native event sources (eBPF / ETW) when privileged and available, else polling.
    #[default]
    Auto,
    /// Polling only (works unprivileged; may miss very short-lived activity).
    Poll,
    /// Native only; startup fails if unavailable.
    Native,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CollectConfig {
    pub backend: CollectBackend,
    pub poll_interval_ms: u64,
    /// Report connections to loopback addresses (normally noise; tests enable it).
    pub include_loopback: bool,
    /// Enable a DNS visibility source when one is available.
    pub dns: bool,
}

impl Default for CollectConfig {
    fn default() -> Self {
        CollectConfig {
            backend: CollectBackend::Auto,
            poll_interval_ms: 1000,
            include_loopback: false,
            dns: true,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Config::default_for_os()
    }
}

impl Default for PathsConfig {
    fn default() -> Self {
        let (data_dir, log_dir, rules_dir) = default_dirs(Os::current());
        PathsConfig {
            data_dir,
            log_dir,
            rules_dir,
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        StorageConfig {
            db_file: PathBuf::from("vigil.db"),
            event_retention_days: 30,
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        LoggingConfig {
            level: "info".into(),
            format: LogFormat::Text,
            to_file: true,
        }
    }
}

impl Config {
    /// Defaults for the OS this binary was built for.
    pub fn default_for_os() -> Self {
        Config {
            mode: ResponseMode::default(),
            paths: PathsConfig::default(),
            storage: StorageConfig::default(),
            logging: LoggingConfig::default(),
            collect: CollectConfig::default(),
            sensitive: SensitiveConfig::default(),
            ipc: IpcConfig::default(),
        }
    }

    /// Default config file location for the current OS.
    pub fn default_path() -> PathBuf {
        default_config_path(Os::current())
    }

    /// Reads, parses, resolves, and validates a config file.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        Config::from_toml_str(&text, base)
    }

    /// Parses TOML, resolves relative paths against `base_dir`, and validates.
    pub fn from_toml_str(s: &str, base_dir: &Path) -> Result<Self, ConfigError> {
        let mut cfg: Config = toml::from_str(s)?;
        cfg.paths.data_dir = resolve(base_dir, &cfg.paths.data_dir);
        cfg.paths.log_dir = resolve(base_dir, &cfg.paths.log_dir);
        cfg.paths.rules_dir = resolve(base_dir, &cfg.paths.rules_dir);
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if !RETENTION_DAYS_RANGE.contains(&self.storage.event_retention_days) {
            return Err(ConfigError::Invalid(format!(
                "storage.event_retention_days must be in {}..={}, got {}",
                RETENTION_DAYS_RANGE.start(),
                RETENTION_DAYS_RANGE.end(),
                self.storage.event_retention_days
            )));
        }
        for (name, p) in [
            ("paths.data_dir", &self.paths.data_dir),
            ("paths.log_dir", &self.paths.log_dir),
            ("paths.rules_dir", &self.paths.rules_dir),
            ("storage.db_file", &self.storage.db_file),
        ] {
            if p.as_os_str().is_empty() {
                return Err(ConfigError::Invalid(format!("{name} must not be empty")));
            }
        }
        if !POLL_INTERVAL_MS_RANGE.contains(&self.collect.poll_interval_ms) {
            return Err(ConfigError::Invalid(format!(
                "collect.poll_interval_ms must be in {}..={}, got {}",
                POLL_INTERVAL_MS_RANGE.start(),
                POLL_INTERVAL_MS_RANGE.end(),
                self.collect.poll_interval_ms
            )));
        }
        for k in self.sensitive.extra_paths.keys() {
            if SensitiveClass::parse(k).is_none() {
                return Err(ConfigError::Invalid(format!(
                    "sensitive.extra_paths: unknown class {k:?}"
                )));
            }
        }
        for k in self.sensitive.extra_persistence.keys() {
            if PersistenceKind::parse(k).is_none() {
                return Err(ConfigError::Invalid(format!(
                    "sensitive.extra_persistence: unknown kind {k:?}"
                )));
            }
        }
        if self.logging.level.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "logging.level must not be empty".into(),
            ));
        }
        Ok(())
    }

    pub fn to_toml_string(&self) -> Result<String, ConfigError> {
        Ok(toml::to_string_pretty(self)?)
    }

    /// Absolute path of the SQLite database.
    pub fn db_path(&self) -> PathBuf {
        resolve(&self.paths.data_dir, &self.storage.db_file)
    }
}

fn resolve(base: &Path, p: &Path) -> PathBuf {
    if p.is_absolute() || p.as_os_str().is_empty() {
        p.to_path_buf()
    } else {
        base.join(p)
    }
}

fn windows_program_data() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
}

fn default_dirs(os: Os) -> (PathBuf, PathBuf, PathBuf) {
    match os {
        Os::Windows => {
            let root = windows_program_data().join("Vigil");
            (root.join("data"), root.join("logs"), root.join("rules"))
        }
        Os::Linux => (
            PathBuf::from("/var/lib/vigil"),
            PathBuf::from("/var/log/vigil"),
            PathBuf::from("/etc/vigil/rules"),
        ),
        Os::MacOs => (
            PathBuf::from("/Library/Application Support/Vigil/data"),
            PathBuf::from("/Library/Logs/Vigil"),
            PathBuf::from("/Library/Application Support/Vigil/rules"),
        ),
    }
}

fn default_config_path(os: Os) -> PathBuf {
    match os {
        Os::Windows => windows_program_data().join("Vigil").join("config.toml"),
        Os::Linux => PathBuf::from("/etc/vigil/config.toml"),
        Os::MacOs => PathBuf::from("/Library/Application Support/Vigil/config.toml"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> PathBuf {
        std::env::temp_dir().join("vigil-config-test")
    }

    #[test]
    fn defaults_validate() {
        let c = Config::default_for_os();
        c.validate().unwrap();
        assert_eq!(c.mode, ResponseMode::Prompt);
        assert_eq!(c.storage.event_retention_days, 30);
        assert!(c.db_path().ends_with("vigil.db"));
    }

    #[test]
    fn empty_file_gives_defaults() {
        let c = Config::from_toml_str("", &base()).unwrap();
        assert_eq!(c, Config::default_for_os());
    }

    #[test]
    fn partial_file_fills_defaults() {
        let c = Config::from_toml_str(
            "mode = \"auto\"\n[storage]\nevent_retention_days = 7\n",
            &base(),
        )
        .unwrap();
        assert_eq!(c.mode, ResponseMode::Auto);
        assert_eq!(c.storage.event_retention_days, 7);
        assert_eq!(c.storage.db_file, PathBuf::from("vigil.db"));
        assert_eq!(c.logging, LoggingConfig::default());
    }

    #[test]
    fn unknown_keys_rejected() {
        let err = Config::from_toml_str("mdoe = \"auto\"\n", &base()).unwrap_err();
        assert!(matches!(err, ConfigError::Parse(_)), "{err}");
        let err = Config::from_toml_str("[storage]\nretention = 3\n", &base()).unwrap_err();
        assert!(matches!(err, ConfigError::Parse(_)), "{err}");
    }

    #[test]
    fn bad_values_rejected() {
        assert!(matches!(
            Config::from_toml_str("mode = \"yolo\"\n", &base()),
            Err(ConfigError::Parse(_))
        ));
        assert!(matches!(
            Config::from_toml_str("[storage]\nevent_retention_days = 0\n", &base()),
            Err(ConfigError::Invalid(_))
        ));
        assert!(matches!(
            Config::from_toml_str("[logging]\nlevel = \"  \"\n", &base()),
            Err(ConfigError::Invalid(_))
        ));
        assert!(matches!(
            Config::from_toml_str("[collect]\npoll_interval_ms = 5\n", &base()),
            Err(ConfigError::Invalid(_))
        ));
        assert!(matches!(
            Config::from_toml_str("[collect]\nbackend = \"magic\"\n", &base()),
            Err(ConfigError::Parse(_))
        ));
    }

    #[test]
    fn sensitive_extras_are_typed_and_validated() {
        let toml = r#"
[sensitive.extra_paths]
browser_passwords = ["/t/profile"]
[sensitive.extra_persistence]
autostart = ["/t/auto"]
"#;
        let c = Config::from_toml_str(toml, &base()).unwrap();
        assert_eq!(
            c.sensitive.classes(),
            vec![(
                SensitiveClass::BrowserPasswords,
                PathBuf::from("/t/profile")
            )]
        );
        assert_eq!(
            c.sensitive.persistence(),
            vec![(PersistenceKind::Autostart, PathBuf::from("/t/auto"))]
        );
        let bad = r#"
[sensitive.extra_paths]
nope = ["/x"]
"#;
        assert!(matches!(
            Config::from_toml_str(bad, &base()),
            Err(ConfigError::Invalid(_))
        ));
    }

    #[test]
    fn relative_paths_resolve_against_base() {
        let b = base();
        let c = Config::from_toml_str("[paths]\ndata_dir = \"data\"\nlog_dir = \"logs\"\n", &b)
            .unwrap();
        assert_eq!(c.paths.data_dir, b.join("data"));
        assert_eq!(c.paths.log_dir, b.join("logs"));
        assert_eq!(c.db_path(), b.join("data").join("vigil.db"));
    }

    #[test]
    fn toml_round_trip() {
        let c = Config::default_for_os();
        let s = c.to_toml_string().unwrap();
        let back = Config::from_toml_str(&s, &base()).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn per_os_defaults_are_absolute() {
        for os in [Os::Windows, Os::Linux, Os::MacOs] {
            let (d, l, r) = default_dirs(os);
            let cfg = default_config_path(os);
            // Windows paths are only "absolute" to std::path on Windows.
            if os == Os::current() {
                assert!(d.is_absolute() && l.is_absolute() && r.is_absolute() && cfg.is_absolute());
            }
            assert!(cfg.ends_with("config.toml"));
        }
    }

    #[test]
    fn example_config_parses_and_documents_the_defaults() {
        let text = include_str!("../../../config/vigil.example.toml");
        let b = base();
        let c = Config::from_toml_str(text, &b).unwrap();
        assert_eq!(c.mode, ResponseMode::default());
        assert_eq!(c.storage, StorageConfig::default());
        assert_eq!(c.logging, LoggingConfig::default());
        assert_eq!(c.collect, CollectConfig::default());
        assert_eq!(c.paths.data_dir, b.join("data"));
        assert_eq!(c.paths.log_dir, b.join("logs"));
        assert_eq!(c.paths.rules_dir, b.join("rules"));
    }

    #[test]
    fn load_reports_missing_file() {
        let err = Config::load(Path::new("definitely/not/here.toml")).unwrap_err();
        assert!(matches!(err, ConfigError::Io { .. }));
        assert!(err.to_string().contains("here.toml"));
    }
}
