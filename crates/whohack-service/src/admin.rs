//! Configuration and database management commands.

use std::path::Path;

use anyhow::{Context, Result};
use whohack_core::{Config, Store};

use crate::logging;

/// Loads and fully validates a config file (including the log filter syntax).
pub fn load_config(path: &Path) -> Result<Config> {
    let cfg = Config::load(path).with_context(|| format!("config {}", path.display()))?;
    logging::parse_filter(&cfg.logging.level)?;
    Ok(cfg)
}

pub fn print_default_config() -> Result<()> {
    let text = Config::default_for_os().to_toml_string()?;
    print!("{text}");
    Ok(())
}

pub fn check_config(path: &Path) -> Result<()> {
    let cfg = load_config(path)?;
    let rules = whohack_detect::rules::RuleSet::load(&cfg.paths.rules_dir.join("tier0"))?;
    if let (Some(model), Some(sha)) = (&cfg.tier1.model, &cfg.tier1.sha256) {
        whohack_detect::onnx::OnnxScorer::load(model, sha)?;
    }
    for path in [&cfg.decision.manifest, &cfg.decision.tier3_manifest]
        .into_iter()
        .flatten()
    {
        let m = whohack_decide::manifest::Manifest::load(path)?;
        println!(
            "model={} revision={} validated={}",
            m.model_name,
            m.revision,
            m.qualified()?
        );
    }
    println!("config ok: {}", path.display());
    println!("mode={}", cfg.mode.as_str());
    println!("db={}", cfg.db_path().display());
    println!("log_dir={}", cfg.paths.log_dir.display());
    println!(
        "rules={}; response_enabled={}; configured_mode={}",
        rules.rules.len(),
        cfg.response.enabled,
        cfg.mode.as_str()
    );
    let intel = cfg.paths.data_dir.join("intel.json");
    if intel.exists() {
        let index =
            whohack_intel::reputation::Reputation::load(&intel, whohack_core::time::now_ms())?;
        println!("threat_indicators={}", index.len());
    }
    Ok(())
}

/// Local setup is opt-in and refuses to overwrite an existing configuration.
pub fn init_local(path: &Path) -> Result<()> {
    use std::io::Write;
    let absolute = std::path::absolute(path)?;
    anyhow::ensure!(
        !absolute.exists(),
        "{} already exists; existing configurations are never overwritten",
        absolute.display()
    );
    let parent = absolute
        .parent()
        .context("configuration needs a parent directory")?;
    let local = parent.join(".vigil");
    std::fs::create_dir_all(parent)?;
    let mut cfg = Config {
        mode: whohack_core::ResponseMode::Monitor,
        ..Config::default()
    };
    cfg.paths.data_dir = local.join("data");
    cfg.paths.log_dir = local.join("logs");
    cfg.paths.rules_dir = std::env::current_dir()?.join("rules");
    cfg.collect.backend = whohack_core::config::CollectBackend::Poll;
    cfg.collect.dns = false;
    #[cfg(unix)]
    {
        // WSL's Windows-mounted filesystems cannot host Unix sockets. Keep the
        // endpoint in the user's native home filesystem, keyed by config path.
        use sha2::Digest;
        let home_dir =
            std::env::var_os("HOME").context("HOME is required for a local Unix IPC endpoint")?;
        let run_dir = std::path::PathBuf::from(home_dir).join(".local/state/whohack");
        std::fs::create_dir_all(&run_dir)?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&run_dir, std::fs::Permissions::from_mode(0o700))?;
        let key =
            whohack_core::hex::encode(&sha2::Sha256::digest(absolute.to_string_lossy().as_bytes()));
        cfg.ipc.endpoint = run_dir
            .join(format!("{}.sock", &key[..16]))
            .to_string_lossy()
            .into_owned();
    }
    #[cfg(windows)]
    {
        cfg.ipc.endpoint = format!(r"\\.\pipe\whohack-local-{}", std::process::id());
    }
    let text = cfg.to_toml_string()?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&absolute)
        .with_context(|| {
            format!(
                "creating {}; existing configurations are never overwritten",
                absolute.display()
            )
        })?;
    file.write_all(text.as_bytes())?;
    std::fs::create_dir_all(&local)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&local, std::fs::Permissions::from_mode(0o700))?;
    }
    println!("Created {}", absolute.display());
    println!(
        "Run: whohack-service --config \"{}\" --run",
        absolute.display()
    );
    println!("Tray: set WHOHACK_CONFIG to the same config path before starting whohack-tray.");
    println!(
        "Monitor-only development setup. Polling observes this OS's processes and TCP activity; no enforcement."
    );
    Ok(())
}

pub fn status(path: &Path) -> Result<()> {
    let cfg = load_config(path)?;
    crate::service::block_on(async {
        let token = whohack_ipc::auth::read_token_file(&cfg.paths.data_dir.join("ipc.token"))
            .context("reading IPC credentials; is the service running?")?;
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let stream = whohack_ipc::transport::connect(&cfg.ipc.endpoint).await?;
            let mut client = whohack_ipc::Client::connect(stream, &token).await?;
            match client.request(whohack_ipc::Request::Status).await? {
                whohack_ipc::Response::Status { status } => {
                    println!("{}", serde_json::to_string_pretty(&status)?)
                }
                response => anyhow::bail!("unexpected status response: {response:?}"),
            }
            Ok::<_, anyhow::Error>(())
        })
        .await
        .context("service status timed out")??;
        Ok(())
    })
}

pub fn write_manifest(path: &Path) -> Result<()> {
    let cfg = load_config(path)?;
    let manifest = crate::integrity::write_manifest(&cfg.paths.rules_dir, Some(path))?;
    println!("manifest written: {}", manifest.display());
    Ok(())
}

pub fn init_db(path: &Path) -> Result<()> {
    let cfg = load_config(path)?;
    let _log = logging::init(&cfg.logging, &cfg.paths.log_dir)?;
    let db = cfg.db_path();
    let store = Store::open(&db).with_context(|| format!("database {}", db.display()))?;
    tracing::info!(db = %db.display(), "database ready");
    println!("db={}", db.display());
    println!("schema_version={}", store.schema_version()?);
    println!("journal_mode={}", store.journal_mode()?);
    println!("tables={}", store.table_names()?.join(","));
    Ok(())
}
