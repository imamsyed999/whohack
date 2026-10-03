//! Logging setup: `tracing` to stderr, plus an optional daily-rolling file.

use anyhow::{Context, Result};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer, Registry};
use vigil_core::config::{LogFormat, LoggingConfig};

/// Keeps the background file writer alive; logs are flushed when dropped.
#[derive(Debug)]
pub struct LogGuard {
    _file: Option<WorkerGuard>,
}

/// Parses a filter directive such as `"info"` or `"info,vigil_core=debug"`.
pub fn parse_filter(directive: &str) -> Result<EnvFilter> {
    EnvFilter::try_new(directive)
        .with_context(|| format!("invalid logging.level filter {directive:?}"))
}

type BoxedLayer = Box<dyn Layer<Registry> + Send + Sync>;

fn fmt_layer<W>(format: LogFormat, writer: W, ansi: bool) -> BoxedLayer
where
    W: for<'w> tracing_subscriber::fmt::MakeWriter<'w> + Send + Sync + 'static,
{
    let base = tracing_subscriber::fmt::layer()
        .with_writer(writer)
        .with_ansi(ansi);
    match format {
        LogFormat::Text => base.boxed(),
        LogFormat::Json => base.json().boxed(),
    }
}

/// Installs the global subscriber. A non-empty `RUST_LOG` overrides the
/// configured level. Call once per process.
pub fn init(cfg: &LoggingConfig, log_dir: &std::path::Path) -> Result<LogGuard> {
    let directive = std::env::var("RUST_LOG")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| cfg.level.clone());
    let filter = parse_filter(&directive)?;

    let mut layers: Vec<BoxedLayer> = vec![fmt_layer(cfg.format, std::io::stderr, false)];
    let mut guard = None;
    if cfg.to_file {
        std::fs::create_dir_all(log_dir)
            .with_context(|| format!("cannot create log directory {}", log_dir.display()))?;
        let appender = RollingFileAppender::builder()
            .rotation(Rotation::DAILY)
            .filename_prefix("vigil-service")
            .filename_suffix("log")
            .build(log_dir)
            .with_context(|| format!("cannot open log file in {}", log_dir.display()))?;
        let (writer, g) = tracing_appender::non_blocking(appender);
        layers.push(fmt_layer(cfg.format, writer, false));
        guard = Some(g);
    }

    tracing_subscriber::registry()
        .with(layers.with_filter(filter))
        .try_init()
        .context("a global tracing subscriber is already installed")?;
    Ok(LogGuard { _file: guard })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_filters() {
        for d in ["info", "warn", "info,vigil_core=debug", "trace"] {
            parse_filter(d).unwrap();
        }
    }

    #[test]
    fn rejects_invalid_filter() {
        let err = parse_filter("info,vigil_core=loud").unwrap_err();
        assert!(format!("{err:#}").contains("logging.level"));
    }
}
