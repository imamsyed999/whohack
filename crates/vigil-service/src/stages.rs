//! Construction of the pipeline's analysis stages from configuration.

use vigil_core::Config;
use vigil_taint::scan::DEFAULT_MAX_SCAN_BYTES;
use vigil_taint::{FileAnalyzer, ProcessTracker, TaintEngine, YaraScanner};

/// Builds the taint stage. YARA rules come from `<rules_dir>/yara`; if they
/// are missing or fail to compile, scanning is disabled with a warning
/// (detection still works without YARA).
pub fn taint_engine(cfg: &Config) -> TaintEngine {
    let dir = cfg.paths.rules_dir.join("yara");
    let yara = match YaraScanner::from_dir(&dir, DEFAULT_MAX_SCAN_BYTES) {
        Ok(s) => {
            tracing::info!(rules = s.rule_count(), dir = %dir.display(), "YARA rules loaded");
            Some(s)
        }
        Err(e) => {
            tracing::warn!(error = %e, "YARA scanning disabled");
            None
        }
    };
    TaintEngine::new(FileAnalyzer::new(yara), ProcessTracker::default())
        .with_cache_file(cfg.paths.data_dir.join("hash-cache.tsv"))
}
