//! Configuration and database management commands.

use std::path::Path;

use anyhow::{Context, Result};
use vigil_core::{Config, Store};

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
    println!("config ok: {}", path.display());
    println!("mode={}", cfg.mode.as_str());
    println!("db={}", cfg.db_path().display());
    println!("log_dir={}", cfg.paths.log_dir.display());
    Ok(())
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
