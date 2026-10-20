//! Explicit, pinned local model installation. No downloads or remote code.
use crate::{DecisionSidecar, SidecarConfig};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub version: u32,
    pub model_name: String,
    pub revision: String,
    pub backend: String,
    pub python: PathBuf,
    pub script: PathBuf,
    pub script_sha256: String,
    pub model_dir: PathBuf,
    pub files: BTreeMap<String, String>,
    pub dtype: String,
    pub threads: u8,
    pub max_state_tokens: usize,
    /// Validation report, inside model_dir and pinned in files. Without this,
    /// model output is advisory and cannot alter a response.
    pub evaluation: Option<String>,
    pub calibration: Option<String>,
    #[serde(default)]
    pub thresholds: whohack_detect::fusion::Thresholds,
}
impl Manifest {
    pub fn load(path: &Path) -> Result<Self> {
        use std::io::Read;
        let mut bytes = vec![];
        std::fs::File::open(path)?
            .take(1_048_577)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 1_048_576, "model manifest exceeds 1 MiB");
        let mut m: Self = serde_json::from_slice(&bytes)?;
        let base = path.parent().unwrap_or(Path::new("."));
        for p in [&mut m.python, &mut m.script, &mut m.model_dir] {
            if p.is_relative() {
                *p = base.join(&*p);
            }
            *p = p
                .canonicalize()
                .with_context(|| format!("model path {}", p.display()))?;
        }
        ensure!(
            m.version == 1 && ["laya", "opendecider"].contains(&m.backend.as_str()),
            "unsupported model manifest"
        );
        ensure!(
            !m.model_name.trim().is_empty() && !m.revision.trim().is_empty(),
            "model identity required"
        );
        ensure!(
            (1..=4).contains(&m.threads) && (128..=1536).contains(&m.max_state_tokens),
            "model resource limits out of range"
        );
        ensure!(
            ["float32", "bfloat16"].contains(&m.dtype.as_str()),
            "unsupported dtype"
        );
        m.thresholds.validate()?;
        m.verify()?;
        Ok(m)
    }
    fn path(&self, name: &str) -> Result<PathBuf> {
        let p = Path::new(name);
        ensure!(
            !p.as_os_str().is_empty()
                && p.components()
                    .all(|c| matches!(c, std::path::Component::Normal(_))),
            "manifest file must be a relative child path"
        );
        let path = self.model_dir.join(p).canonicalize()?;
        ensure!(
            path.starts_with(&self.model_dir),
            "model file escapes model directory"
        );
        Ok(path)
    }
    pub fn verify(&self) -> Result<()> {
        crate::sidecar::verify_file(&self.script, &self.script_sha256)?;
        let required: &[&str] = match self.backend.as_str() {
            "laya" => &[
                "rl_agent_config.json",
                "encoder/config.json",
                "tokenizer/tokenizer.json",
                "tokenizer/tokenizer_config.json",
                "model.safetensors",
            ],
            "opendecider" => &[
                "config.json",
                "tokenizer.json",
                "model.safetensors",
                "head.safetensors",
            ],
            _ => anyhow::bail!("unsupported model backend"),
        };
        ensure!(
            required.iter().all(|name| self.files.contains_key(*name)),
            "manifest must pin config, tokenizer, and safetensors weights"
        );
        ensure!(
            self.backend != "laya" || self.dtype == "float32",
            "Laya's verified adapter requires float32"
        );
        let mut pinned = BTreeMap::new();
        for (name, sha) in &self.files {
            let path = self.path(name)?;
            pinned.insert(path.clone(), sha.clone());
            crate::sidecar::verify_file(&path, sha)?;
        }
        // Every model-consumed file must be pinned; an injected config/shard may
        // otherwise change what from_pretrained loads despite a pinned main file.
        verify_model_tree(&self.model_dir, &pinned)?;
        Ok(())
    }
    pub fn qualified(&self) -> Result<bool> {
        let Some(name) = &self.evaluation else {
            return Ok(false);
        };
        ensure!(
            self.files.contains_key(name),
            "evaluation report must be pinned"
        );
        let Some(cal) = &self.calibration else {
            anyhow::bail!("qualified model requires calibration");
        };
        ensure!(self.files.contains_key(cal), "calibration must be pinned");
        use std::io::Read;
        let path = self.path(name)?;
        crate::sidecar::verify_file(&path, &self.files[name])?;
        let mut bytes = Vec::new();
        std::fs::File::open(path)?
            .take(1_048_577)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 1_048_576, "evaluation report exceeds 1 MiB");
        let v: serde_json::Value = serde_json::from_slice(&bytes)?;
        let evaluated_thresholds: whohack_detect::fusion::Thresholds =
            serde_json::from_value(v["thresholds"].clone())
                .context("evaluation must record fusion thresholds")?;
        ensure!(
            evaluated_thresholds == self.thresholds,
            "evaluation thresholds differ from the runtime policy"
        );
        ensure!(
            v["model_name"].as_str() == Some(self.model_name.as_str())
                && v["model_revision"].as_str() == Some(self.revision.as_str()),
            "evaluation belongs to a different model revision"
        );
        for (key, file) in [
            ("weights_sha256", "model.safetensors"),
            ("head_sha256", "head.safetensors"),
            ("calibration_sha256", cal.as_str()),
        ] {
            ensure!(
                v[key].as_str() == self.files.get(file).map(String::as_str),
                "evaluation does not match pinned {file}"
            );
        }
        ensure!(
            v["schema_version"] == 1
                && v["family_disjoint"] == true
                && v["synthetic"] == false
                && v["device"] == "cpu"
                && v["passed"] == true,
            "model quality gate failed"
        );
        for (key, min) in [
            ("malicious_cases", 100),
            ("benign_cases", 200),
            ("malicious_families", 5),
        ] {
            ensure!(
                v[key].as_u64().is_some_and(|n| n >= min),
                "quality requirement {key} failed"
            );
        }
        let replay = &v["benign_replay"];
        let hours = replay["duration_hours"]
            .as_f64()
            .filter(|n| n.is_finite() && *n >= 168.)
            .context("measured benign week is required")?;
        let alerts = replay["alerts"]
            .as_u64()
            .context("benign alert count is required")?;
        ensure!(
            replay["synthetic"] == false
                && replay["apps"].as_u64().is_some_and(|n| n >= 200)
                && replay["source"]
                    .as_str()
                    .is_some_and(|s| !s.trim().is_empty()),
            "representative benign replay is required"
        );
        let week = alerts as f64 * 168. / hours;
        ensure!(
            week <= 1.
                && v["alerts_per_week"]
                    .as_f64()
                    .is_some_and(|n| (n - week).abs() < 1e-6),
            "benign week metric does not match replay"
        );
        for (key, min) in [("malicious_recall", 0.9), ("human_review_fraction", 0.1)] {
            ensure!(
                v[key]
                    .as_f64()
                    .is_some_and(|n| n.is_finite() && n >= min && n <= 1.),
                "quality requirement {key} failed"
            );
        }
        for (key, max) in [
            ("benign_fpr", 0.01),
            ("alerts_per_week", 1.),
            ("cpu_p95_ms", 3000.),
            ("rss_mb", 1200.),
        ] {
            ensure!(
                v[key]
                    .as_f64()
                    .is_some_and(|n| n.is_finite() && n >= 0. && n <= max),
                "quality requirement {key} failed"
            );
        }
        ensure!(
            v["cpu_p95_ms"].as_f64().is_some_and(|n| n > 0.)
                && v["rss_mb"].as_f64().is_some_and(|n| n > 0.),
            "measured CPU latency and RSS are required"
        );
        Ok(true)
    }
    pub fn sidecar(&self, tier3: bool) -> Result<DecisionSidecar> {
        let mut pinned = BTreeMap::from([(self.script.clone(), self.script_sha256.clone())]);
        for (name, sha) in &self.files {
            pinned.insert(self.path(name)?, sha.clone());
        }
        let mut args = vec![
            "--backend".into(),
            self.backend.clone(),
            "--model-dir".into(),
            self.model_dir.to_string_lossy().into_owned(),
            "--device".into(),
            "cpu".into(),
            "--threads".into(),
            self.threads.to_string(),
            "--dtype".into(),
            self.dtype.clone(),
        ];
        if tier3 {
            args.extend(["--min-ram-gb".into(), "16".into()]);
        }
        if let Some(cal) = &self.calibration {
            ensure!(self.files.contains_key(cal), "calibration must be pinned");
            args.extend([
                "--calibration".into(),
                self.path(cal)?.to_string_lossy().into_owned(),
            ]);
        }
        Ok(DecisionSidecar::new(SidecarConfig {
            python: self.python.clone(),
            script: self.script.clone(),
            args,
            model_name: format!("{}@{}", self.model_name, self.revision),
            max_state_tokens: self.max_state_tokens,
            pinned,
            model_dir: Some(self.model_dir.clone()),
            idle_unload: Duration::from_secs(600),
        }))
    }
}

/// Rechecked before each child start, including after idle unloading. New model
/// files must not change from_pretrained behavior after the initial pin check.
pub(crate) fn verify_model_tree(root: &Path, pinned: &BTreeMap<PathBuf, String>) -> Result<()> {
    fn visit(
        dir: &Path,
        pinned: &BTreeMap<PathBuf, String>,
        depth: usize,
        count: &mut usize,
        size: &mut u64,
    ) -> Result<()> {
        ensure!(depth <= 16, "model directory is nested too deeply");
        for e in std::fs::read_dir(dir)? {
            let e = e?;
            *count += 1;
            ensure!(*count <= 4096, "too many model files/directories");
            let kind = e.file_type()?;
            ensure!(
                !kind.is_symlink(),
                "symlinks are not allowed in model directories"
            );
            if kind.is_dir() {
                if e.file_name() != ".cache" {
                    visit(&e.path(), pinned, depth + 1, count, size)?;
                }
                continue;
            }
            ensure!(kind.is_file(), "model inputs must be regular files");
            *size = size
                .checked_add(e.metadata()?.len())
                .context("model size overflow")?;
            ensure!(
                *size <= 8 * 1024 * 1024 * 1024,
                "model directory exceeds 8 GiB"
            );
            let path = e.path();
            let ext = path
                .extension()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            ensure!(
                !["bin", "pt", "pth", "pkl", "pickle", "py"].contains(&ext.as_str()),
                "executable/pickle model files are not supported"
            );
            ensure!(
                pinned.contains_key(&path.canonicalize()?),
                "unpinned model file {}",
                path.display()
            );
        }
        Ok(())
    }
    visit(root, pinned, 0, &mut 0, &mut 0)
}
