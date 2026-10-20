//! Command-line interface.

use std::path::PathBuf;

use clap::error::ErrorKind;
use clap::{Args, CommandFactory, Parser};

#[derive(Debug, Parser)]
#[command(
    name = "whohack-service",
    version,
    about = "whohack anti-hack detection service"
)]
pub struct Cli {
    /// Config file (default: the per-OS system location). Replay loads rules and
    /// Tier 1 only when --config is explicit; without it replay uses built-ins.
    #[arg(long, value_name = "PATH", global = true)]
    pub config: Option<PathBuf>,

    /// With --monitor: stop after this many seconds (default: run until Ctrl-C).
    #[arg(long, value_name = "SECS")]
    pub duration_secs: Option<u64>,

    /// With --monitor: do not write events to the database.
    #[arg(long)]
    pub no_store: bool,

    /// With --run: exit gracefully when this launcher session marker changes.
    #[arg(long, value_name = "PATH")]
    pub session_file: Option<PathBuf>,

    /// Category to compare during offline replay.
    #[arg(long, default_value = "other")]
    pub category: String,
    /// With --replay: ask a pinned local model, without applying any OS response.
    #[arg(long, value_name = "PATH")]
    pub model_manifest: Option<PathBuf>,

    #[command(flatten)]
    action: ActionArgs,
}

#[derive(Debug, Args)]
#[group(required = true, multiple = false)]
struct ActionArgs {
    /// Print the versioned questions and feature order for dataset tools.
    #[arg(long)]
    model_contract: bool,
    /// Create whohack.local.toml and private local data paths for development.
    #[arg(long)]
    init_local: bool,

    /// Query the running service over authenticated local IPC.
    #[arg(long)]
    status: bool,
    /// Analyze a JSONL fixture offline; never changes OS policy or executes files.
    #[arg(long, value_name = "PATH")]
    replay: Option<PathBuf>,
    /// Print the default configuration for this OS as TOML and exit.
    #[arg(long)]
    print_default_config: bool,

    /// Load and validate the configuration, then exit 0 (valid) or 1 (invalid).
    #[arg(long)]
    check_config: bool,

    /// Create or migrate the event database, print its status, and exit.
    #[arg(long)]
    init_db: bool,

    /// Collect live events and print network connections per process.
    #[arg(long)]
    monitor: bool,

    /// Run the service: collect, analyze, store, and serve the tray UI over IPC.
    #[arg(long)]
    run: bool,

    /// Regenerate the integrity manifest for the rules directory and config file.
    #[arg(long)]
    write_manifest: bool,

    /// Windows: register whohack as an auto-start service and start it (administrator).
    #[arg(long)]
    install_service: bool,

    /// Windows: stop and remove the whohack service (administrator).
    #[arg(long)]
    uninstall_service: bool,

    /// Windows: entry point used by the Service Control Manager.
    #[arg(long, hide = true)]
    service: bool,
}

/// The single action selected on the command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    ModelContract,
    InitLocal,
    Status,
    Replay,
    PrintDefaultConfig,
    CheckConfig,
    InitDb,
    Monitor,
    Run,
    WriteManifest,
    InstallService,
    UninstallService,
    Service,
}

impl Cli {
    pub fn replay_path(&self) -> Option<&std::path::Path> {
        self.action.replay.as_deref()
    }
    /// Cross-argument checks clap cannot express for boolean flags.
    pub fn validate(self) -> Result<Self, clap::Error> {
        if self.model_manifest.is_some() && self.action() != Command::Replay {
            return Err(Cli::command().error(
                ErrorKind::ArgumentConflict,
                "--model-manifest requires --replay",
            ));
        }
        if self.session_file.is_some() && self.action() != Command::Run {
            return Err(
                Cli::command().error(ErrorKind::ArgumentConflict, "--session-file requires --run")
            );
        }
        if self.action() != Command::Replay && self.category != "other" {
            return Err(
                Cli::command().error(ErrorKind::ArgumentConflict, "--category requires --replay")
            );
        }
        if !whohack_tags::profile::CATEGORIES.contains(&self.category.as_str()) {
            return Err(Cli::command().error(ErrorKind::InvalidValue, "unknown behavior category"));
        }
        if self.action() != Command::Monitor && (self.duration_secs.is_some() || self.no_store) {
            return Err(Cli::command().error(
                ErrorKind::ArgumentConflict,
                "--duration-secs and --no-store can only be used with --monitor",
            ));
        }
        Ok(self)
    }

    pub fn action(&self) -> Command {
        // clap's ArgGroup guarantees exactly one flag is set.
        let a = &self.action;
        if a.model_contract {
            Command::ModelContract
        } else if a.init_local {
            Command::InitLocal
        } else if a.status {
            Command::Status
        } else if a.replay.is_some() {
            Command::Replay
        } else if a.print_default_config {
            Command::PrintDefaultConfig
        } else if a.check_config {
            Command::CheckConfig
        } else if a.init_db {
            Command::InitDb
        } else if a.monitor {
            Command::Monitor
        } else if a.run {
            Command::Run
        } else if a.write_manifest {
            Command::WriteManifest
        } else if a.install_service {
            Command::InstallService
        } else if a.uninstall_service {
            Command::UninstallService
        } else {
            Command::Service
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(args).and_then(Cli::validate)
    }

    #[test]
    fn clap_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_each_action() {
        let c = Cli::try_parse_from(["whohack-service", "--print-default-config"]).unwrap();
        assert_eq!(c.action(), Command::PrintDefaultConfig);
        let c = Cli::try_parse_from(["whohack-service", "--config", "x.toml", "--check-config"])
            .unwrap();
        assert_eq!(c.action(), Command::CheckConfig);
        assert_eq!(c.config, Some(PathBuf::from("x.toml")));
        let c = Cli::try_parse_from(["whohack-service", "--init-db"]).unwrap();
        assert_eq!(c.action(), Command::InitDb);
        let c = Cli::try_parse_from(["whohack-service", "--run"]).unwrap();
        assert_eq!(c.action(), Command::Run);
        let c = Cli::try_parse_from([
            "whohack-service",
            "--monitor",
            "--duration-secs",
            "5",
            "--no-store",
        ])
        .unwrap();
        assert_eq!(c.action(), Command::Monitor);
        assert_eq!(c.duration_secs, Some(5));
        assert!(c.no_store);
    }

    #[test]
    fn requires_exactly_one_action() {
        assert!(Cli::try_parse_from(["whohack-service"]).is_err());
        assert!(Cli::try_parse_from(["whohack-service", "--init-db", "--check-config"]).is_err());
    }

    #[test]
    fn monitor_options_require_monitor() {
        assert!(parse(&["whohack-service", "--init-db", "--duration-secs", "1"]).is_err());
        assert!(parse(&["whohack-service", "--init-db", "--no-store"]).is_err());
        assert!(parse(&["whohack-service", "--monitor", "--no-store"]).is_ok());
        assert!(parse(&["whohack-service", "--run", "--session-file", "session"]).is_ok());
        assert!(
            parse(&[
                "whohack-service",
                "--install-service",
                "--session-file",
                "session"
            ])
            .is_err()
        );
    }
}
