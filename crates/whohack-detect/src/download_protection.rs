//! Conservative deterministic qualification for a reversible process pause.
//! A download, signature absence, new destination or beacon alone is insufficient.
use whohack_core::{EventKind, Observation};

pub fn should_pause(obs: &Observation, detection: &crate::Detection) -> bool {
    let Some(p) = &obs.process else {
        return false;
    };
    if !p.tainted {
        return false;
    }
    // A local matched signature (including explicitly installed test signatures)
    // is independent of unqualified model probabilities and heuristic scores.
    if detection.rule_ids.iter().any(|r| r == "yara-match") {
        return true;
    }
    let has = |tag: &str| obs.tags.iter().any(|t| t.as_str() == tag);
    match obs.event.kind {
        EventKind::NetConnect { .. } => has("network:intel_hit"),
        EventKind::Injection { .. } => has("injection:remote_thread"),
        EventKind::FileAccess { write: false, .. } => {
            // A browser/password manager may read its own store after opening
            // downloaded content. Trusted applications require user review.
            let untrusted = p.script.as_ref().unwrap_or(&p.exe).sign.is_untrusted();
            untrusted
                && [
                    "credential_access:browser_passwords",
                    "credential_access:keychain",
                    "credential_access:ssh_keys",
                    "credential_access:crypto_wallets",
                    "credential_access:lsass",
                ]
                .iter()
                .any(|tag| has(tag))
        }
        _ => false,
    }
}
