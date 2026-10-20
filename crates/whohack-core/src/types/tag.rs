use std::borrow::Cow;
use std::fmt;

use serde::{Deserialize, Serialize};

/// A capability tag such as `"credential_access:browser_passwords"` (SPEC §9).
///
/// Deviation from SPEC §7: the spec declares `CapabilityTag(pub &'static str)`,
/// but tags must round-trip through SQLite and IPC, and serde cannot
/// deserialize into `&'static str`. `Cow<'static, str>` keeps the static
/// taxonomy table allocation-free via [`CapabilityTag::from_static`] while
/// allowing owned tags when read back.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CapabilityTag(pub Cow<'static, str>);

impl CapabilityTag {
    pub const fn from_static(s: &'static str) -> Self {
        CapabilityTag(Cow::Borrowed(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Part before the `:` (e.g. `"credential_access"`); the whole tag if there is no colon.
    pub fn family(&self) -> &str {
        self.0.split_once(':').map_or(&self.0, |(f, _)| f)
    }
}

impl fmt::Display for CapabilityTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for CapabilityTag {
    fn from(s: String) -> Self {
        CapabilityTag(Cow::Owned(s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BROWSER: CapabilityTag =
        CapabilityTag::from_static("credential_access:browser_passwords");

    #[test]
    fn static_and_owned_compare_equal() {
        let owned = CapabilityTag::from("credential_access:browser_passwords".to_string());
        assert_eq!(BROWSER, owned);
        assert_eq!(BROWSER.family(), "credential_access");
        assert_eq!(CapabilityTag::from_static("plain").family(), "plain");
    }

    #[test]
    fn serializes_as_plain_string() {
        let s = serde_json::to_string(&BROWSER).unwrap();
        assert_eq!(s, "\"credential_access:browser_passwords\"");
        let back: CapabilityTag = serde_json::from_str(&s).unwrap();
        assert_eq!(back, BROWSER);
        assert_eq!(back.to_string(), BROWSER.as_str());
    }
}
