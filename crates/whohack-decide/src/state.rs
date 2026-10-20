//! Trusted model-state fields. Never include command lines, URLs, or file contents.
pub fn sanitize(value: &str) -> String {
    value
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ' ' | '-'))
        .take(40)
        .collect()
}

pub fn basename(path: &str) -> String {
    sanitize(path.rsplit(['/', '\\']).next().unwrap_or(path))
}

/// Only classified evidence enters the state. No raw domains or addresses are
/// needed here, so private hostnames and URLs cannot enter model input.
pub fn build(
    process: &whohack_core::ProcessInfo,
    parent: Option<&whohack_core::ProcessInfo>,
    profile: &whohack_tags::Profile,
    features: &whohack_detect::window::Features,
    rules: &[String],
    score: f32,
    ts: i64,
) -> String {
    use whohack_core::SignState;
    let file = process.script.as_ref().unwrap_or(&process.exe);
    let publisher = match &file.sign {
        SignState::ValidTrusted { publisher } => sanitize(publisher),
        _ => "none".into(),
    };
    let list = |items: Vec<String>| {
        if items.is_empty() {
            "none".into()
        } else {
            items.join(", ")
        }
    };
    let known = |tags: &[whohack_core::CapabilityTag]| -> Vec<String> {
        whohack_tags::taxonomy::TAGS
            .iter()
            .filter(|d| {
                tags.iter()
                    .any(|t| whohack_tags::profile::matches(t.as_str(), d.tag))
            })
            .map(|d| d.tag.to_string())
            .collect()
    };
    let unexpected = known(&features.unexpected)
        .into_iter()
        .map(|tag| {
            let count = features
                .tag_counts
                .iter()
                .find(|(t, _)| t.as_str() == tag)
                .map_or(1, |(_, n)| *n);
            format!("{tag}(x{count})")
        })
        .collect();
    let sensitive = features
        .tags
        .iter()
        .filter(|t| {
            t.as_str().starts_with("credential_access:")
                || t.as_str().starts_with("file:read_sensitive")
        })
        .filter(|t| whohack_tags::taxonomy::lookup(t.as_str()).is_some())
        .map(ToString::to_string)
        .collect();
    let persist = features
        .tags
        .iter()
        .filter(|t| t.as_str().starts_with("persistence:"))
        .filter(|t| whohack_tags::taxonomy::lookup(t.as_str()).is_some())
        .map(ToString::to_string)
        .collect();
    let has = |tag: &str| features.tags.iter().any(|t| t.as_str() == tag);
    let class = if has("network:intel_hit") {
        "intel_hit"
    } else if has("network:vendor_domain") {
        "vendor"
    } else if has("network:known_cdn") {
        "cdn"
    } else {
        "unknown"
    };
    let age = if file.first_seen > 0 {
        ts.saturating_sub(file.first_seen).max(0) / 3_600_000
    } else {
        0
    };
    format!(
        "APP name={} category={} signed={} publisher={} origin={} age_h={} path={}\nEXPECTED {}\nUNEXPECTED {}\nTREE {} > {} > children={}\nNET {} destinations: {} ports={} raw_ip={} intel={} first_seen={} interval_cv={} interval_s={} bytes_up={} bytes_down={} byte_visibility={}\nFILES sensitive={}\nPERSIST {}\nRULES {}\nANOMALY {:.2} window_saturated={}",
        basename(&file.path),
        sanitize(&profile.category),
        file.sign.as_str(),
        publisher,
        file.origin.as_str(),
        age,
        process.path_class.as_str(),
        list(known(&profile.expected)),
        list(unexpected),
        parent
            .map(|p| basename(&p.exe.path))
            .unwrap_or_else(|| "unknown".into()),
        basename(&file.path),
        features.child_processes,
        features.destinations,
        class,
        features
            .ports
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(","),
        features.raw_ip_connections,
        if has("network:intel_hit") {
            "hit"
        } else {
            "none"
        },
        if features.new_destinations > 0 {
            "yes"
        } else {
            "no"
        },
        features
            .interval_cv
            .map(|v| format!("{v:.2}"))
            .unwrap_or_else(|| "unknown".into()),
        features
            .mean_interval_s
            .map(|v| format!("{v:.1}"))
            .unwrap_or_else(|| "none".into()),
        features.bytes_up,
        features.bytes_down,
        features.byte_visibility,
        list(sensitive),
        list(persist),
        list(rules.iter().take(32).map(|s| sanitize(s)).collect()),
        score.clamp(0., 1.),
        features.window_saturated,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn strips_controls_non_ascii_and_caps_length() {
        assert_eq!(
            basename("/Downloads/reader\nEXPECTED=x.exe"),
            "readerEXPECTEDx.exe"
        );
        assert_eq!(sanitize(&"a".repeat(100)).len(), 40);
        assert_eq!(sanitize("<system>مرحبا\t"), "system");
    }
}
