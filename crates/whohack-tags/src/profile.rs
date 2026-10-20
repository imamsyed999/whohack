use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use whohack_core::CapabilityTag;

use crate::taxonomy::{TAGS, lookup};

pub const CATEGORIES: &[&str] = &[
    "browser",
    "office_document",
    "pdf_reader",
    "media_player",
    "game",
    "game_launcher",
    "chat_messaging",
    "developer_tool",
    "ide",
    "terminal",
    "system_utility",
    "driver_or_hardware_tool",
    "vpn_or_network_tool",
    "security_tool",
    "installer_updater",
    "archive_tool",
    "password_manager",
    "crypto_wallet",
    "other",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CategoryTemplate {
    pub category: String,
    pub expected: Vec<String>,
    pub never: Vec<String>,
}

/// Only exact tags and a family wildcard are supported. Arbitrary globs cannot
/// accidentally grant permissions across unrelated capability families.
pub fn matches(pattern: &str, tag: &str) -> bool {
    pattern == tag
        || pattern
            .strip_suffix('*')
            .is_some_and(|p| p.ends_with(':') && tag.starts_with(p))
}

pub fn valid_pattern(pattern: &str) -> bool {
    lookup(pattern).is_some()
        || (pattern.ends_with(":*") && TAGS.iter().any(|d| matches(pattern, d.tag)))
}

impl CategoryTemplate {
    pub fn from_yaml(text: &str) -> Result<Self> {
        let value: Self = serde_saphyr::from_str(text)?;
        ensure!(
            CATEGORIES.contains(&value.category.as_str()),
            "unknown category: {}",
            value.category
        );
        for p in value.expected.iter().chain(&value.never) {
            ensure!(valid_pattern(p), "unknown tag pattern: {p}");
        }
        for d in TAGS {
            ensure!(
                !(value.expected.iter().any(|p| matches(p, d.tag))
                    && value.never.iter().any(|p| matches(p, d.tag))),
                "expected and never overlap: {}",
                d.tag
            );
        }
        Ok(value)
    }

    pub fn builtin(category: &str) -> Result<Self> {
        let text = BUILTINS
            .iter()
            .find(|(c, _)| *c == category)
            .map(|(_, s)| *s)
            .ok_or_else(|| anyhow::anyhow!("unknown category: {category}"))?;
        Self::from_yaml(text)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub category: String,
    pub expected: Vec<CapabilityTag>,
    pub never: Vec<String>,
    pub learning_until: Option<i64>,
}

impl Profile {
    pub fn from_template(template: CategoryTemplate, learning_until: Option<i64>) -> Self {
        Self {
            category: template.category,
            expected: template.expected.into_iter().map(Into::into).collect(),
            never: template.never,
            learning_until,
        }
    }
    pub fn unexpected(&self, tags: &[CapabilityTag]) -> Vec<CapabilityTag> {
        tags.iter()
            .filter(|t| {
                self.never.iter().any(|p| matches(p, t.as_str()))
                    || !self
                        .expected
                        .iter()
                        .any(|p| matches(p.as_str(), t.as_str()))
            })
            .cloned()
            .collect()
    }
    pub fn violates_never(&self, tags: &[CapabilityTag]) -> Vec<CapabilityTag> {
        tags.iter()
            .filter(|t| self.never.iter().any(|p| matches(p, t.as_str())))
            .cloned()
            .collect()
    }
}

const BUILTINS: &[(&str, &str)] = &[
    ("browser", include_str!("../../../profiles/browser.yaml")),
    (
        "office_document",
        include_str!("../../../profiles/office_document.yaml"),
    ),
    (
        "pdf_reader",
        include_str!("../../../profiles/pdf_reader.yaml"),
    ),
    (
        "media_player",
        include_str!("../../../profiles/media_player.yaml"),
    ),
    ("game", include_str!("../../../profiles/game.yaml")),
    (
        "game_launcher",
        include_str!("../../../profiles/game_launcher.yaml"),
    ),
    (
        "chat_messaging",
        include_str!("../../../profiles/chat_messaging.yaml"),
    ),
    (
        "developer_tool",
        include_str!("../../../profiles/developer_tool.yaml"),
    ),
    ("ide", include_str!("../../../profiles/ide.yaml")),
    ("terminal", include_str!("../../../profiles/terminal.yaml")),
    (
        "system_utility",
        include_str!("../../../profiles/system_utility.yaml"),
    ),
    (
        "driver_or_hardware_tool",
        include_str!("../../../profiles/driver_or_hardware_tool.yaml"),
    ),
    (
        "vpn_or_network_tool",
        include_str!("../../../profiles/vpn_or_network_tool.yaml"),
    ),
    (
        "security_tool",
        include_str!("../../../profiles/security_tool.yaml"),
    ),
    (
        "installer_updater",
        include_str!("../../../profiles/installer_updater.yaml"),
    ),
    (
        "archive_tool",
        include_str!("../../../profiles/archive_tool.yaml"),
    ),
    (
        "password_manager",
        include_str!("../../../profiles/password_manager.yaml"),
    ),
    (
        "crypto_wallet",
        include_str!("../../../profiles/crypto_wallet.yaml"),
    ),
    ("other", include_str!("../../../profiles/other.yaml")),
];

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_templates_validate_and_pdf_never_wins() {
        assert_eq!(BUILTINS.len(), CATEGORIES.len());
        for c in CATEGORIES {
            assert_eq!(CategoryTemplate::builtin(c).unwrap().category, *c);
        }
        let mut p = Profile::from_template(CategoryTemplate::builtin("pdf_reader").unwrap(), None);
        let bad = CapabilityTag::from_static("credential_access:browser_passwords");
        p.expected.push(bad.clone());
        assert_eq!(p.unexpected(std::slice::from_ref(&bad)), vec![bad.clone()]);
        assert_eq!(p.violates_never(std::slice::from_ref(&bad)), vec![bad]);
        assert!(!matches("credential_access:*", "network:beaconing"));
        assert!(!valid_pattern("*"));
        assert!(!valid_pattern("invented:*"));
    }
    #[test]
    fn rejects_invalid_or_conflicting_templates() {
        assert!(
            CategoryTemplate::from_yaml("category: other\nexpected: [invented:tag]\nnever: []")
                .is_err()
        );
        assert!(
            CategoryTemplate::from_yaml(
                "category: other\nexpected: [network:beaconing]\nnever: ['network:*']"
            )
            .is_err()
        );
    }
}
