use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use whohack_core::{Action, Observation, PathClass};
use whohack_tags::profile::{matches, valid_pattern};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    pub description: String,
    pub severity: Severity,
    pub action_floor: Action,
    #[serde(rename = "match")]
    pub condition: Condition,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Condition {
    pub tags: Vec<String>,
    pub tainted: Option<bool>,
    pub sign: Option<Vec<String>>,
    pub path_class: Option<Vec<PathClass>>,
    pub not_path_class: Option<Vec<PathClass>>,
}

impl Rule {
    fn validate(&self) -> Result<()> {
        ensure!(
            !self.id.is_empty()
                && self.id.len() <= 64
                && self
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
            "invalid rule id"
        );
        ensure!(
            !self.description.trim().is_empty(),
            "{}: empty description",
            self.id
        );
        ensure!(
            !self.condition.tags.is_empty(),
            "{}: match.tags must not be empty",
            self.id
        );
        for tag in &self.condition.tags {
            ensure!(valid_pattern(tag), "{}: unknown tag {tag}", self.id);
        }
        if let Some(signs) = &self.condition.sign {
            ensure!(
                !signs.is_empty()
                    && signs.iter().all(|s| matches!(
                        s.as_str(),
                        "valid_trusted" | "valid_untrusted" | "invalid" | "unsigned"
                    )),
                "{}: invalid sign states",
                self.id
            );
        }
        for list in [&self.condition.path_class, &self.condition.not_path_class]
            .into_iter()
            .flatten()
        {
            ensure!(!list.is_empty(), "{}: empty path class condition", self.id);
        }
        if self.severity == Severity::Critical {
            ensure!(
                self.action_floor >= Action::BlockNetwork,
                "{}: critical floor must be at least block_network",
                self.id
            );
        }
        Ok(())
    }

    pub fn matches(&self, obs: &Observation) -> bool {
        if !self
            .condition
            .tags
            .iter()
            .all(|pattern| obs.tags.iter().any(|t| matches(pattern, t.as_str())))
        {
            return false;
        }
        let c = &self.condition;
        if c.tainted.is_none()
            && c.sign.is_none()
            && c.path_class.is_none()
            && c.not_path_class.is_none()
        {
            return true;
        }
        let Some(p) = &obs.process else {
            return false;
        };
        let file = p.script.as_ref().unwrap_or(&p.exe);
        c.tainted.is_none_or(|t| t == p.tainted)
            && c.sign
                .as_ref()
                .is_none_or(|s| s.iter().any(|s| s == file.sign.as_str()))
            && c.path_class
                .as_ref()
                .is_none_or(|s| s.contains(&p.path_class))
            && c.not_path_class
                .as_ref()
                .is_none_or(|s| !s.contains(&p.path_class))
    }
}

#[derive(Debug, Clone)]
pub struct RuleSet {
    pub rules: Vec<Rule>,
}

impl RuleSet {
    pub fn from_yaml(text: &str) -> Result<Self> {
        let rules: Vec<Rule> = serde_saphyr::from_str(text)?;
        ensure!(rules.len() <= 1024, "too many rules");
        let mut ids = std::collections::HashSet::new();
        for rule in &rules {
            rule.validate()?;
            ensure!(ids.insert(&rule.id), "duplicate rule {}", rule.id);
        }
        Ok(Self { rules })
    }
    pub fn builtin() -> Self {
        Self::from_yaml(include_str!("../../../rules/tier0/builtin.yaml"))
            .expect("bundled rules validated by tests")
    }
    /// Built-ins plus local overrides. A malformed update leaves the caller's
    /// current set untouched; call this before swapping the running engine.
    pub fn load(dir: &Path) -> Result<Self> {
        let mut rules: BTreeMap<_, _> = Self::builtin()
            .rules
            .into_iter()
            .map(|r| (r.id.clone(), r))
            .collect();
        if !dir.exists() {
            return Ok(Self {
                rules: rules.into_values().collect(),
            });
        }
        let mut paths = std::fs::read_dir(dir)?
            .map(|e| e.map(|e| e.path()))
            .collect::<std::io::Result<Vec<_>>>()?;
        paths.sort();
        let mut custom_ids = std::collections::HashSet::new();
        for path in paths
            .into_iter()
            .filter(|p| matches!(p.extension().and_then(|s| s.to_str()), Some("yaml" | "yml")))
        {
            use std::io::Read;
            let mut text = String::new();
            std::fs::File::open(&path)?
                .take(1_048_577)
                .read_to_string(&mut text)?;
            ensure!(text.len() <= 1_048_576, "{}: exceeds 1 MiB", path.display());
            let set =
                Self::from_yaml(&text).with_context(|| format!("loading {}", path.display()))?;
            for r in set.rules {
                ensure!(
                    custom_ids.insert(r.id.clone()),
                    "duplicate custom rule {}",
                    r.id
                );
                rules.insert(r.id.clone(), r);
                ensure!(rules.len() <= 1024, "too many rules");
            }
        }
        Ok(Self {
            rules: rules.into_values().collect(),
        })
    }
}
