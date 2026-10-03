//! Command-line interface.

use std::path::PathBuf;

use clap::error::ErrorKind;
use clap::{Args, CommandFactory, Parser};

#[derive(Debug, Parser)]
#[command(
    name = "vigil-service",
    version,
    about = "Vigil anti-hack detection service"
)]
pub struct Cli {
    /// Config file (default: the per-OS system location).
    #[arg(long, value_name = "PATH", global = true)]
    pub config: Option<PathBuf>,

    /// With --monitor: stop after this many seconds (default: run until Ctrl-C).
    #[arg(long, value_name = "SECS")]
    pub duration_secs: Option<u64>,

    /// With --monitor: do not write events to the database.
    #[arg(long)]
    pub no_store: bool,

    #[command(flatten)]
    action: ActionArgs,
}

#[derive(Debug, Args)]
#[group(required = true, multiple = false)]
struct ActionArgs {
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
}

/// The single action selected on the command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    PrintDefaultConfig,
    CheckConfig,
    InitDb,
    Monitor,
    Run,
}

impl Cli {
    /// Cross-argument checks clap cannot express for boolean flags.
    pub fn validate(self) -> Result<Self, clap::Error> {
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
        if a.print_default_config {
            Command::PrintDefaultConfig
        } else if a.check_config {
            Command::CheckConfig
        } else if a.init_db {
            Command::InitDb
        } else if a.monitor {
            Command::Monitor
        } else {
            Command::Run
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
        let c = Cli::try_parse_from(["vigil-service", "--print-default-config"]).unwrap();
        assert_eq!(c.action(), Command::PrintDefaultConfig);
        let c =
            Cli::try_parse_from(["vigil-service", "--config", "x.toml", "--check-config"]).unwrap();
        assert_eq!(c.action(), Command::CheckConfig);
        assert_eq!(c.config, Some(PathBuf::from("x.toml")));
        let c = Cli::try_parse_from(["vigil-service", "--init-db"]).unwrap();
        assert_eq!(c.action(), Command::InitDb);
        let c = Cli::try_parse_from(["vigil-service", "--run"]).unwrap();
        assert_eq!(c.action(), Command::Run);
        let c = Cli::try_parse_from([
            "vigil-service",
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
        assert!(Cli::try_parse_from(["vigil-service"]).is_err());
        assert!(Cli::try_parse_from(["vigil-service", "--init-db", "--check-config"]).is_err());
    }

    #[test]
    fn monitor_options_require_monitor() {
        assert!(parse(&["vigil-service", "--init-db", "--duration-secs", "1"]).is_err());
        assert!(parse(&["vigil-service", "--init-db", "--no-store"]).is_err());
        assert!(parse(&["vigil-service", "--monitor", "--no-store"]).is_ok());
    }
}
