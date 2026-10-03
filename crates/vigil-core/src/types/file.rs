use serde::{Deserialize, Serialize};

/// Where an executable came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Origin {
    /// Fetched from the internet (Mark-of-the-Web, quarantine xattr, XDG origin xattr,
    /// or first written to a watched download/temp directory).
    Downloaded {
        url: Option<String>,
        referrer: Option<String>,
    },
    /// Installed by a package manager or a trusted installer.
    Installed,
    /// Part of the operating system.
    System,
    Unknown,
}

impl Origin {
    /// Stable lowercase label, as used in the decision-model state (SPEC §12.3).
    pub const fn as_str(&self) -> &'static str {
        match self {
            Origin::Downloaded { .. } => "downloaded",
            Origin::Installed => "installed",
            Origin::System => "system",
            Origin::Unknown => "unknown",
        }
    }

    pub const fn is_downloaded(&self) -> bool {
        matches!(self, Origin::Downloaded { .. })
    }
}

/// Code-signature state of an executable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SignState {
    ValidTrusted { publisher: String },
    ValidUntrusted,
    Invalid,
    Unsigned,
}

impl SignState {
    pub const fn as_str(&self) -> &'static str {
        match self {
            SignState::ValidTrusted { .. } => "valid_trusted",
            SignState::ValidUntrusted => "valid_untrusted",
            SignState::Invalid => "invalid",
            SignState::Unsigned => "unsigned",
        }
    }

    /// True for anything other than a valid, trusted signature.
    pub const fn is_untrusted(&self) -> bool {
        !matches!(self, SignState::ValidTrusted { .. })
    }
}

/// Coarse classification of where an executable lives on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathClass {
    Downloads,
    Temp,
    ProgramFiles,
    System,
    UserApp,
    Other,
}

impl PathClass {
    pub const ALL: [PathClass; 6] = [
        PathClass::Downloads,
        PathClass::Temp,
        PathClass::ProgramFiles,
        PathClass::System,
        PathClass::UserApp,
        PathClass::Other,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            PathClass::Downloads => "downloads",
            PathClass::Temp => "temp",
            PathClass::ProgramFiles => "program_files",
            PathClass::System => "system",
            PathClass::UserApp => "user_app",
            PathClass::Other => "other",
        }
    }

    pub fn parse(s: &str) -> Option<PathClass> {
        PathClass::ALL.into_iter().find(|c| c.as_str() == s)
    }
}

/// Everything Vigil knows about one file on disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileInfo {
    pub path: String,
    #[serde(with = "crate::hex::sha256")]
    pub sha256: [u8; 32],
    pub origin: Origin,
    pub sign: SignState,
    pub yara_hits: Vec<String>,
    /// Unix ms when Vigil first saw this file.
    pub first_seen: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> FileInfo {
        FileInfo {
            path: "C:\\Users\\a\\Downloads\\setup.exe".into(),
            sha256: [0xab; 32],
            origin: Origin::Downloaded {
                url: Some("https://example.com/setup.exe".into()),
                referrer: None,
            },
            sign: SignState::Unsigned,
            yara_hits: vec!["eicar".into()],
            first_seen: 1_700_000_000_000,
        }
    }

    #[test]
    fn file_info_round_trip_with_hex_digest() {
        let f = sample();
        let json = serde_json::to_value(&f).unwrap();
        assert_eq!(json["sha256"], "ab".repeat(32));
        assert_eq!(json["origin"]["type"], "downloaded");
        let back: FileInfo = serde_json::from_value(json).unwrap();
        assert_eq!(back, f);
    }

    #[test]
    fn rejects_short_digest() {
        let mut json = serde_json::to_value(sample()).unwrap();
        json["sha256"] = "abcd".into();
        assert!(serde_json::from_value::<FileInfo>(json).is_err());
    }

    #[test]
    fn origin_and_sign_round_trip() {
        for o in [
            Origin::Downloaded {
                url: None,
                referrer: Some("r".into()),
            },
            Origin::Installed,
            Origin::System,
            Origin::Unknown,
        ] {
            let s = serde_json::to_string(&o).unwrap();
            assert_eq!(serde_json::from_str::<Origin>(&s).unwrap(), o);
        }
        for st in [
            SignState::ValidTrusted {
                publisher: "Contoso".into(),
            },
            SignState::ValidUntrusted,
            SignState::Invalid,
            SignState::Unsigned,
        ] {
            let s = serde_json::to_string(&st).unwrap();
            assert_eq!(serde_json::from_str::<SignState>(&s).unwrap(), st);
        }
    }

    #[test]
    fn labels() {
        assert_eq!(Origin::Installed.as_str(), "installed");
        assert!(
            Origin::Downloaded {
                url: None,
                referrer: None
            }
            .is_downloaded()
        );
        assert!(SignState::Unsigned.is_untrusted());
        assert!(
            !SignState::ValidTrusted {
                publisher: "x".into()
            }
            .is_untrusted()
        );
        for c in PathClass::ALL {
            assert_eq!(PathClass::parse(c.as_str()), Some(c));
            assert_eq!(
                serde_json::to_string(&c).unwrap(),
                format!("\"{}\"", c.as_str())
            );
        }
        assert_eq!(PathClass::parse("nope"), None);
    }
}
