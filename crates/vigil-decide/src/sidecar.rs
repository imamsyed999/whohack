//! `DecisionSidecar`: runs the typed-decision model in a separate process
//! speaking JSON lines over stdin/stdout (protocol v1, see
//! `docs/research/decision-models.md` §9).
//!
//! - Started lazily on the first `decide`; files are verified against pinned
//!   SHA-256 hashes before every start.
//! - `ready` must arrive within [`READY_TIMEOUT`]; each request gets
//!   [`DECIDE_TIMEOUT`]. On timeout or a broken pipe the process is killed
//!   and restarted on the next call.
//! - Unloaded after [`IDLE_UNLOAD`] without requests (checked on each call
//!   and by [`DecisionSidecar::reap_idle`]).
//! - stderr lines are forwarded to `tracing`.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::Mutex;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::model::{Answer, DecisionModel, QKind, Question};

pub const PROTOCOL: u32 = 1;
pub const READY_TIMEOUT: Duration = Duration::from_secs(60);
pub const DECIDE_TIMEOUT: Duration = Duration::from_secs(10);
pub const IDLE_UNLOAD: Duration = Duration::from_secs(10 * 60);

/// How to start the sidecar.
#[derive(Debug, Clone)]
pub struct SidecarConfig {
    /// Python interpreter (bundled in releases).
    pub python: PathBuf,
    /// The sidecar script.
    pub script: PathBuf,
    /// Extra arguments, e.g. `--backend opendecider --model-dir ... --device cpu --threads 2`.
    pub args: Vec<String>,
    /// Display name, e.g. `"opendecider-nano@<revision>"`.
    pub model_name: String,
    pub max_state_tokens: usize,
    /// Files that must match a SHA-256 (hex) before the sidecar starts.
    pub pinned: BTreeMap<PathBuf, String>,
    pub idle_unload: Duration,
}

struct Proc {
    child: Child,
    stdin: ChildStdin,
    lines: Receiver<String>,
    last_used: Instant,
    next_id: u64,
}

impl Proc {
    fn kill(mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub struct DecisionSidecar {
    cfg: SidecarConfig,
    proc: Mutex<Option<Proc>>,
}

impl std::fmt::Debug for DecisionSidecar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecisionSidecar")
            .field("model", &self.cfg.model_name)
            .finish()
    }
}

/// Verifies `path` against an expected SHA-256 (hex).
pub fn verify_file(path: &Path, expected_hex: &str) -> Result<()> {
    let mut f = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = std::io::Read::read(&mut f, &mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    let got = vigil_core::hex::encode(&h.finalize());
    if !got.eq_ignore_ascii_case(expected_hex) {
        bail!(
            "{} has sha256 {got}, expected {expected_hex}",
            path.display()
        );
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct WireAnswer {
    id: String,
    labels: Vec<String>,
    probs: Vec<f32>,
}

/// Builds the protocol request for `state` and `qs`.
pub fn request_json(id: u64, state: &str, qs: &[Question]) -> Value {
    let questions: Vec<Value> = qs
        .iter()
        .map(|q| match &q.kind {
            QKind::YesNo => json!({"id": q.id, "kind": "yes_no", "text": q.text}),
            QKind::Choice(_) => {
                json!({"id": q.id, "kind": "choice", "text": q.text, "options": q.kind.labels()})
            }
            QKind::Score { .. } => {
                json!({"id": q.id, "kind": "score", "text": q.text, "options": q.kind.labels()})
            }
        })
        .collect();
    json!({"id": id.to_string(), "op": "decide", "state": state, "questions": questions})
}

/// Parses a decide response into answers, in request order.
pub fn parse_response(line: &str, id: u64, qs: &[Question]) -> Result<Vec<Answer>> {
    let v: Value = serde_json::from_str(line).context("sidecar sent invalid JSON")?;
    if v.get("id").and_then(Value::as_str) != Some(id.to_string().as_str()) {
        bail!("sidecar response id mismatch");
    }
    if v.get("ok").and_then(Value::as_bool) != Some(true) {
        let msg = v
            .pointer("/error/message")
            .and_then(Value::as_str)
            .unwrap_or("unknown error");
        bail!("sidecar error: {msg}");
    }
    if v.pointer("/usage/truncated").and_then(Value::as_bool) == Some(true) {
        tracing::warn!("decision state was truncated by the model");
    }
    let answers: Vec<WireAnswer> =
        serde_json::from_value(v.get("answers").cloned().unwrap_or(Value::Null))?;
    qs.iter()
        .map(|q| {
            let a = answers
                .iter()
                .find(|a| a.id == q.id)
                .ok_or_else(|| anyhow!("no answer for question {}", q.id))?;
            if a.labels.len() != a.probs.len() {
                bail!("answer {} has mismatched labels/probs", q.id);
            }
            Ok(Answer {
                id: a.id.clone(),
                probs: a
                    .labels
                    .iter()
                    .cloned()
                    .zip(a.probs.iter().copied())
                    .collect(),
            })
        })
        .collect()
}

impl DecisionSidecar {
    pub fn new(cfg: SidecarConfig) -> Self {
        DecisionSidecar {
            cfg,
            proc: Mutex::new(None),
        }
    }

    pub fn is_loaded(&self) -> bool {
        self.proc.lock().map(|p| p.is_some()).unwrap_or(false)
    }

    fn spawn(&self) -> Result<Proc> {
        for (path, hash) in &self.cfg.pinned {
            verify_file(path, hash)?;
        }
        let mut child = Command::new(&self.cfg.python)
            .arg(&self.cfg.script)
            .args(&self.cfg.args)
            .env("HF_HUB_OFFLINE", "1")
            .env("TRANSFORMERS_OFFLINE", "1")
            .env("PYTHONUNBUFFERED", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("starting {}", self.cfg.python.display()))?;
        let stdin = child.stdin.take().ok_or_else(|| anyhow!("no stdin"))?;
        let stdout = child.stdout.take().ok_or_else(|| anyhow!("no stdout"))?;
        if let Some(stderr) = child.stderr.take() {
            std::thread::spawn(move || {
                for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                    tracing::debug!(target: "vigil_decide::sidecar", "{line}");
                }
            });
        }
        let (tx, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let p = Proc {
            child,
            stdin,
            lines,
            last_used: Instant::now(),
            next_id: 1,
        };
        let ready = match p.lines.recv_timeout(READY_TIMEOUT) {
            Ok(l) => l,
            Err(e) => {
                p.kill();
                bail!("sidecar did not become ready: {e}");
            }
        };
        let v: Value = serde_json::from_str(&ready).context("invalid ready line")?;
        if v.get("type").and_then(Value::as_str) != Some("ready")
            || v.get("protocol").and_then(Value::as_u64) != Some(u64::from(PROTOCOL))
        {
            p.kill();
            bail!("unexpected sidecar handshake: {ready}");
        }
        tracing::info!(model = %self.cfg.model_name, "decision model loaded");
        Ok(p)
    }

    /// Unloads the model if it has been idle longer than the configured period.
    pub fn reap_idle(&self) {
        if let Ok(mut guard) = self.proc.lock()
            && guard
                .as_ref()
                .is_some_and(|p| p.last_used.elapsed() >= self.cfg.idle_unload)
            && let Some(mut p) = guard.take()
        {
            let _ = writeln!(p.stdin, "{}", json!({"id": "s", "op": "shutdown"}));
            let _ = p.stdin.flush();
            let deadline = Instant::now() + Duration::from_secs(2);
            while Instant::now() < deadline {
                if matches!(p.child.try_wait(), Ok(Some(_))) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            p.kill();
            tracing::info!(model = %self.cfg.model_name, "decision model unloaded (idle)");
        }
    }
}

impl Drop for DecisionSidecar {
    fn drop(&mut self) {
        if let Ok(mut g) = self.proc.lock()
            && let Some(p) = g.take()
        {
            p.kill();
        }
    }
}

impl DecisionModel for DecisionSidecar {
    fn name(&self) -> &str {
        &self.cfg.model_name
    }

    fn max_state_tokens(&self) -> usize {
        self.cfg.max_state_tokens
    }

    fn decide(&self, state: &str, qs: &[Question]) -> Result<Vec<Answer>> {
        self.reap_idle();
        let mut guard = self
            .proc
            .lock()
            .map_err(|_| anyhow!("sidecar lock poisoned"))?;
        if guard.is_none() {
            *guard = Some(self.spawn()?);
        }
        let p = guard
            .as_mut()
            .ok_or_else(|| anyhow!("sidecar not running"))?;
        let id = p.next_id;
        p.next_id += 1;
        p.last_used = Instant::now();
        let req = request_json(id, state, qs);
        let sent = writeln!(p.stdin, "{req}").and_then(|()| p.stdin.flush());
        let result = match sent {
            Err(e) => Err(anyhow!("sidecar pipe broken: {e}")),
            Ok(()) => match p.lines.recv_timeout(DECIDE_TIMEOUT) {
                Ok(line) => parse_response(&line, id, qs),
                Err(RecvTimeoutError::Timeout) => {
                    Err(anyhow!("sidecar timed out after {DECIDE_TIMEOUT:?}"))
                }
                Err(RecvTimeoutError::Disconnected) => Err(anyhow!("sidecar exited")),
            },
        };
        if result.is_err()
            && let Some(p) = guard.take()
        {
            p.kill(); // restarted lazily on the next call
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn qs() -> Vec<Question> {
        vec![
            Question {
                id: "a",
                kind: QKind::YesNo,
                text: "t".into(),
            },
            Question {
                id: "b",
                kind: QKind::Score { min: 0, max: 3 },
                text: "t".into(),
            },
        ]
    }

    #[test]
    fn request_shape() {
        let v = request_json(7, "STATE", &qs());
        assert_eq!(v["op"], "decide");
        assert_eq!(v["id"], "7");
        assert_eq!(v["questions"][0]["kind"], "yes_no");
        assert!(v["questions"][0].get("options").is_none());
        assert_eq!(v["questions"][1]["options"], json!(["0", "1", "2", "3"]));
    }

    #[test]
    fn response_parsing() {
        let line = r#"{"id":"7","ok":true,"answers":[{"id":"b","labels":["0","1","2","3"],"logits":[0,0,0,0],"probs":[0.1,0.2,0.3,0.4],"temperature":1.0},{"id":"a","labels":["yes","no"],"logits":[0,0],"probs":[0.25,0.75],"temperature":1.0}],"usage":{"truncated":false}}"#;
        let a = parse_response(line, 7, &qs()).unwrap();
        assert_eq!(a[0].id, "a", "request order kept");
        assert_eq!(a[0].prob("no"), 0.75);
        assert_eq!(a[1].top(), Some(("3", 0.4)));
        assert!(parse_response(line, 8, &qs()).is_err(), "id mismatch");
        let err = r#"{"id":"7","ok":false,"error":{"code":"bad_request","message":"nope"}}"#;
        assert!(
            parse_response(err, 7, &qs())
                .unwrap_err()
                .to_string()
                .contains("nope")
        );
    }

    #[test]
    fn pinned_hash_check() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("m.bin");
        std::fs::write(&f, b"abc").unwrap();
        verify_file(
            &f,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )
        .unwrap();
        assert!(verify_file(&f, &"0".repeat(64)).is_err());
    }
}
