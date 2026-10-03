//! `vigil-service`: the privileged Vigil core service.

use std::process::ExitCode;

use anyhow::Result;
use clap::Parser;
use vigil_core::Config;

use vigil_service::cli::{Cli, Command};
use vigil_service::{admin, monitor, service};

fn main() -> ExitCode {
    let cli = Cli::parse().validate().unwrap_or_else(|e| e.exit());
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: &Cli) -> Result<()> {
    let config_path = cli.config.clone().unwrap_or_else(Config::default_path);
    match cli.action() {
        Command::PrintDefaultConfig => admin::print_default_config(),
        Command::CheckConfig => admin::check_config(&config_path),
        Command::InitDb => admin::init_db(&config_path),
        Command::Monitor => {
            let cfg = admin::load_config(&config_path)?;
            monitor::run(&cfg, cli.duration_secs, cli.no_store)
        }
        Command::Run => service::run(&admin::load_config(&config_path)?),
    }
}
