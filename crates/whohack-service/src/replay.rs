//! Offline replay. Declared process metadata is fixture data; never execute paths,
//! resolve domains, or apply OS responses while replaying.
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use whohack_core::{CapabilityTag, Event, Observation, Os, ProcessInfo};
use whohack_tags::{CategoryTemplate, Profile, Tagger};

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayRecord {
    pub event: Event,
    pub process: Option<ProcessInfo>,
}

#[derive(Debug, Serialize)]
pub struct ReplayResult {
    pub score: f32,
    pub scorer: &'static str,
    pub feature_vector: [f32; 17],
    pub state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<serde_json::Value>,
    pub features: whohack_detect::window::Features,
    pub detection: Option<whohack_detect::Detection>,
    pub ts: i64,
    pub pid: u32,
    pub tags: Vec<CapabilityTag>,
    pub unexpected: Vec<CapabilityTag>,
    pub never: Vec<CapabilityTag>,
}

pub fn run(path: &Path, category: &str) -> Result<()> {
    run_with_model(path, category, None)
}

pub fn run_with_model(path: &Path, category: &str, manifest: Option<&Path>) -> Result<()> {
    run_with_config(path, category, manifest, None)
}

pub fn run_with_config(
    path: &Path,
    category: &str,
    manifest: Option<&Path>,
    config: Option<&whohack_core::Config>,
) -> Result<()> {
    use whohack_decide::DecisionModel;
    let model = manifest
        .map(whohack_decide::manifest::Manifest::load)
        .transpose()?
        .map(|m| m.sidecar(false))
        .transpose()?;
    let profile = Profile::from_template(CategoryTemplate::builtin(category)?, None);
    let mut tagger = match config {
        Some(c) => Tagger::new(c.collect.dns, Os::current(), &c.sensitive),
        None => Tagger::new(true, Os::current(), &Default::default()),
    };
    let rules = match config {
        Some(c) => whohack_detect::rules::RuleSet::load(&c.paths.rules_dir.join("tier0"))?,
        None => whohack_detect::rules::RuleSet::builtin(),
    };
    let scorer = config
        .and_then(|c| c.tier1.model.as_ref().zip(c.tier1.sha256.as_ref()))
        .map(|(path, sha)| whohack_detect::onnx::OnnxScorer::load(path, sha))
        .transpose()?;
    let mut windows = whohack_detect::window::Windows::default();
    let input =
        std::fs::File::open(path).with_context(|| format!("opening replay {}", path.display()))?;
    let mut input = BufReader::new(input);
    let mut out = std::io::stdout().lock();
    let mut line = Vec::new();
    let mut number = 0;
    loop {
        line.clear();
        // Bound before deserializing; a malformed fixture cannot allocate an unbounded line.
        use std::io::Read;
        if input
            .by_ref()
            .take(1_048_577)
            .read_until(b'\n', &mut line)?
            == 0
        {
            break;
        }
        number += 1;
        ensure!(
            line.len() <= 1_048_576,
            "replay line {number} exceeds 1 MiB"
        );
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let record: ReplayRecord =
            serde_json::from_slice(&line).with_context(|| format!("replay line {number}"))?;
        let mut result = analyze_configured(
            record,
            &mut tagger,
            &profile,
            &mut windows,
            &rules,
            scorer.as_ref(),
        )?;
        if let (Some(model), Some(text)) = (&model, &result.state) {
            result.decision = Some(
                match model.decide(text, &whohack_decide::questions::runtime()) {
                    Ok(answers) => {
                        serde_json::json!({"model": model.name(), "answers": answers, "applied_action": "none (offline replay)"})
                    }
                    Err(e) => {
                        serde_json::json!({"model": model.name(), "error": e.to_string(), "applied_action": "none (offline replay)"})
                    }
                },
            );
        }
        serde_json::to_writer(&mut out, &result)?;
        writeln!(out)?;
    }
    Ok(())
}

pub fn analyze(
    record: ReplayRecord,
    tagger: &mut Tagger,
    profile: &Profile,
) -> Result<ReplayResult> {
    analyze_with_windows(
        record,
        tagger,
        profile,
        &mut whohack_detect::window::Windows::default(),
    )
}

pub fn analyze_with_windows(
    record: ReplayRecord,
    tagger: &mut Tagger,
    profile: &Profile,
    windows: &mut whohack_detect::window::Windows,
) -> Result<ReplayResult> {
    analyze_configured(
        record,
        tagger,
        profile,
        windows,
        &whohack_detect::rules::RuleSet::builtin(),
        None,
    )
}

pub fn analyze_configured(
    record: ReplayRecord,
    tagger: &mut Tagger,
    profile: &Profile,
    windows: &mut whohack_detect::window::Windows,
    rules: &whohack_detect::rules::RuleSet,
    scorer: Option<&whohack_detect::onnx::OnnxScorer>,
) -> Result<ReplayResult> {
    if let Some(p) = &record.process {
        ensure!(
            p.pid == record.event.pid,
            "fixture process PID differs from event PID"
        );
    }
    let mut obs = Observation {
        event: record.event,
        process: record.process.map(Arc::new),
        tags: vec![],
    };
    tagger.tag(&mut obs);
    let features = windows.observe(&obs, profile);
    let score = match scorer {
        Some(s) => s
            .score(&features)
            .context("configured replay scorer failed")?,
        None => features.heuristic(),
    };
    let mut context = obs.clone();
    context.tags = features.tags.clone();
    let mut detection = whohack_detect::evaluate(&context, profile, rules, &[]);
    if let Some(d) = &mut detection {
        d.score = score;
        d.features = Some(features.clone());
    }
    Ok(ReplayResult {
        score,
        scorer: if scorer.is_some() {
            "onnx"
        } else {
            "heuristic"
        },
        feature_vector: features.vector(),
        decision: None,
        state: obs.process.as_ref().map(|p| {
            whohack_decide::state::build(
                p,
                windows
                    .process(p.ppid)
                    .filter(|parent| parent.start_time <= p.start_time),
                profile,
                &features,
                &detection
                    .as_ref()
                    .map(|d| d.rule_ids.clone())
                    .unwrap_or_default(),
                score,
                obs.event.ts,
            )
        }),
        features,
        detection,
        ts: obs.event.ts,
        pid: obs.event.pid,
        unexpected: profile.unexpected(&obs.tags),
        never: profile.violates_never(&obs.tags),
        tags: obs.tags,
    })
}
