//! `whohack-service`: the privileged whohack core service.

use std::process::ExitCode;

use anyhow::Result;
use clap::Parser;
use whohack_core::Config;

use whohack_service::cli::{Cli, Command};
use whohack_service::{admin, monitor, service};

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
        Command::ModelContract => {
            let questions =
                whohack_decide::sidecar::request_json(0, "", &whohack_decide::questions::runtime())
                    ["questions"]
                    .clone();
            // Serialize f32 thresholds directly before embedding so the shared
            // JSON contract retains their shortest decimal representation.
            let thresholds: serde_json::Value = serde_json::from_str(&serde_json::to_string(
                &whohack_detect::fusion::Thresholds::default(),
            )?)?;
            println!(
                "{}",
                serde_json::json!({"version": 1, "features": whohack_detect::window::FEATURE_NAMES, "questions": questions, "thresholds": thresholds})
            );
            Ok(())
        }
        Command::InitLocal => admin::init_local(
            cli.config
                .as_deref()
                .unwrap_or(std::path::Path::new("whohack.local.toml")),
        ),
        Command::Status => admin::status(&config_path),
        Command::Replay => whohack_service::replay::run_with_config(
            cli.replay_path().expect("clap validated replay"),
            &cli.category,
            cli.model_manifest.as_deref(),
            cli.config
                .as_deref()
                .map(Config::load)
                .transpose()?
                .as_ref(),
        ),
        Command::PrintDefaultConfig => admin::print_default_config(),
        Command::CheckConfig => admin::check_config(&config_path),
        Command::InitDb => admin::init_db(&config_path),
        Command::Monitor => {
            let cfg = admin::load_config(&config_path)?;
            monitor::run(&cfg, cli.duration_secs, cli.no_store)
        }
        Command::Run => {
            let cfg = admin::load_config(&config_path)?;
            if let Some(path) = &cli.session_file {
                let session = whohack_core::local_session::LocalSession::open(path)?;
                service::run_until(&cfg, &config_path, async {
                    tokio::select! {
                        _ = session.ended() => {},
                        _ = service::shutdown_signal() => {},
                    }
                })
            } else {
                service::run(&cfg, &config_path)
            }
        }
        Command::WriteManifest => admin::write_manifest(&config_path),
        #[cfg(windows)]
        Command::InstallService => {
            whohack_service::winservice::install(&config_path)?;
            println!("whohack service installed and started");
            Ok(())
        }
        #[cfg(windows)]
        Command::UninstallService => {
            whohack_service::winservice::uninstall()?;
            println!("whohack service removed");
            Ok(())
        }
        #[cfg(windows)]
        Command::Service => whohack_service::winservice::dispatch(config_path),
        #[cfg(not(windows))]
        Command::InstallService | Command::UninstallService | Command::Service => anyhow::bail!(
            "service installation on this OS is handled by the package (systemd unit / launchd plist); see packaging/README.md"
        ),
    }
}
