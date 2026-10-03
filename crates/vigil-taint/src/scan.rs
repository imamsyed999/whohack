//! YARA scanning of executables and scripts on first sight (yara-x).
//!
//! Rules are compiled from `*.yar` / `*.yara` files in a directory
//! (default `rules/yara`). Files larger than the size limit are skipped, and
//! each scan has a time limit. Built without the `yara` feature, the scanner
//! compiles no rules and reports no matches.

use std::path::Path;
#[cfg(feature = "yara")]
use std::time::Duration;

/// Default largest file scanned (bytes).
pub const DEFAULT_MAX_SCAN_BYTES: u64 = 64 * 1024 * 1024;
#[cfg(feature = "yara")]
const SCAN_TIMEOUT: Duration = Duration::from_secs(5);

pub struct YaraScanner {
    #[cfg(feature = "yara")]
    rules: yara_x::Rules,
    rule_count: usize,
    max_bytes: u64,
}

impl std::fmt::Debug for YaraScanner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("YaraScanner")
            .field("rule_count", &self.rule_count)
            .field("max_bytes", &self.max_bytes)
            .finish()
    }
}

impl YaraScanner {
    /// Compiles `(name, source)` pairs. Errors name the offending source.
    pub fn from_sources(sources: &[(String, String)], max_bytes: u64) -> Result<Self, String> {
        #[cfg(feature = "yara")]
        {
            let mut compiler = yara_x::Compiler::new();
            for (name, src) in sources {
                compiler
                    .add_source(src.as_str())
                    .map_err(|e| format!("YARA rule file {name}: {e}"))?;
            }
            let rules = compiler.build();
            let rule_count = rules.iter().count();
            Ok(YaraScanner {
                rules,
                rule_count,
                max_bytes,
            })
        }
        #[cfg(not(feature = "yara"))]
        {
            let _ = sources;
            Ok(YaraScanner {
                rule_count: 0,
                max_bytes,
            })
        }
    }

    /// Compiles every `*.yar` / `*.yara` file in `dir` (sorted by name).
    pub fn from_dir(dir: &Path, max_bytes: u64) -> Result<Self, String> {
        let mut files: Vec<_> = std::fs::read_dir(dir)
            .map_err(|e| format!("YARA rules directory {}: {e}", dir.display()))?
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| matches!(p.extension().and_then(|e| e.to_str()), Some("yar" | "yara")))
            .collect();
        files.sort();
        let mut sources = Vec::with_capacity(files.len());
        for f in files {
            let src = std::fs::read_to_string(&f).map_err(|e| format!("{}: {e}", f.display()))?;
            sources.push((f.display().to_string(), src));
        }
        YaraScanner::from_sources(&sources, max_bytes)
    }

    pub fn rule_count(&self) -> usize {
        self.rule_count
    }

    /// Identifiers of matching rules for in-memory data.
    pub fn scan_bytes(&self, data: &[u8]) -> Vec<String> {
        #[cfg(feature = "yara")]
        {
            if self.rule_count == 0 || data.len() as u64 > self.max_bytes {
                return Vec::new();
            }
            let mut scanner = yara_x::Scanner::new(&self.rules);
            scanner.set_timeout(SCAN_TIMEOUT);
            match scanner.scan(data) {
                Ok(results) => results
                    .matching_rules()
                    .map(|r| r.identifier().to_string())
                    .collect(),
                Err(e) => {
                    tracing::debug!(error = %e, "YARA scan failed");
                    Vec::new()
                }
            }
        }
        #[cfg(not(feature = "yara"))]
        {
            let _ = data;
            Vec::new()
        }
    }

    /// Identifiers of matching rules for a file (skipped above the size limit).
    pub fn scan_file(&self, path: &Path) -> Vec<String> {
        if self.rule_count == 0 {
            return Vec::new();
        }
        match std::fs::metadata(path) {
            Ok(md) if md.is_file() && md.len() <= self.max_bytes => {}
            _ => return Vec::new(),
        }
        match std::fs::read(path) {
            Ok(data) => self.scan_bytes(&data),
            Err(_) => Vec::new(),
        }
    }
}

#[cfg(all(test, feature = "yara"))]
mod tests {
    use super::*;

    fn bundled() -> YaraScanner {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules/yara");
        YaraScanner::from_dir(&dir, DEFAULT_MAX_SCAN_BYTES).unwrap()
    }

    #[test]
    fn bundled_rules_compile() {
        assert!(bundled().rule_count() >= 1);
    }

    #[test]
    fn eicar_marker_matches_benign_does_not() {
        let s = bundled();
        // Built at runtime and scanned in memory so no test-pattern file is
        // ever written to disk (the OS antivirus would rightly flag it).
        let sample = format!("vigil test {} end", "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!");
        assert_eq!(
            s.scan_bytes(sample.as_bytes()),
            vec!["EICAR_Test_File".to_string()]
        );
        assert!(s.scan_bytes(b"perfectly ordinary bytes").is_empty());
        let big = format!("{}{}", sample, "x".repeat(300));
        assert!(s.scan_bytes(big.as_bytes()).is_empty(), "rule limits size");
    }

    #[test]
    fn size_limit_and_bad_rules() {
        let s = YaraScanner::from_sources(
            &[(
                "t".into(),
                "rule t { strings: $a = \"abc\" condition: $a }".into(),
            )],
            4,
        )
        .unwrap();
        assert_eq!(s.scan_bytes(b"abc"), vec!["t".to_string()]);
        assert!(s.scan_bytes(b"xxabc").is_empty(), "over size limit");
        let err =
            YaraScanner::from_sources(&[("broken.yar".into(), "rule {".into())], 10).unwrap_err();
        assert!(err.contains("broken.yar"), "{err}");
    }
}
