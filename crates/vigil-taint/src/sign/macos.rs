//! macOS code signatures via the system `codesign` tool.
//!
//! The output parser is OS-independent (and tested everywhere); only
//! [`check`] runs the tool.

use vigil_core::SignState;

#[cfg(target_os = "macos")]
use super::SignVerdict;

/// Classifies `codesign -dv --verbose=2` output (stderr) given whether
/// `codesign --verify --strict` succeeded.
///
/// - Apple-issued distribution identities (Developer ID, Mac App Store,
///   Apple's own software) → `ValidTrusted`.
/// - Ad-hoc or development signatures → `ValidUntrusted`.
/// - A signature that fails verification → `Invalid`.
pub fn classify(verify_ok: bool, display: &str) -> SignState {
    if display.contains("not signed at all") {
        return SignState::Unsigned;
    }
    if !verify_ok {
        return SignState::Invalid;
    }
    if display.lines().any(|l| l.trim() == "Signature=adhoc") {
        return SignState::ValidUntrusted;
    }
    let authority = display
        .lines()
        .find_map(|l| l.trim().strip_prefix("Authority="))
        .unwrap_or("");
    if let Some(name) = authority.strip_prefix("Developer ID Application: ") {
        return SignState::ValidTrusted {
            publisher: name.to_string(),
        };
    }
    if authority == "Software Signing" || authority.starts_with("Apple Mac OS Application Signing")
    {
        return SignState::ValidTrusted {
            publisher: "Apple".into(),
        };
    }
    SignState::ValidUntrusted
}

#[cfg(target_os = "macos")]
pub fn check(path: &std::path::Path) -> SignVerdict {
    use std::process::Command;
    let verify_ok = Command::new("/usr/bin/codesign")
        .args(["--verify", "--strict"])
        .arg(path)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    let display = Command::new("/usr/bin/codesign")
        .args(["-dv", "--verbose=2"])
        .arg(path)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stderr).into_owned())
        .unwrap_or_default();
    SignVerdict {
        state: classify(verify_ok, &display),
        package_owned: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn developer_id_is_trusted() {
        let out = "Executable=/Applications/Google Chrome.app/Contents/MacOS/Google Chrome\n\
Identifier=com.google.Chrome\nAuthority=Developer ID Application: Google LLC (EQHXZ8M8AV)\n\
Authority=Developer ID Certification Authority\nAuthority=Apple Root CA\nTeamIdentifier=EQHXZ8M8AV\n";
        assert_eq!(
            classify(true, out),
            SignState::ValidTrusted {
                publisher: "Google LLC (EQHXZ8M8AV)".into()
            }
        );
        assert_eq!(classify(false, out), SignState::Invalid);
    }

    #[test]
    fn apple_adhoc_unsigned() {
        assert_eq!(
            classify(
                true,
                "Identifier=com.apple.ls\nAuthority=Software Signing\nAuthority=Apple Code Signing Certification Authority\n"
            ),
            SignState::ValidTrusted {
                publisher: "Apple".into()
            }
        );
        assert_eq!(
            classify(
                true,
                "Identifier=a.out\nSignature=adhoc\nTeamIdentifier=not set\n"
            ),
            SignState::ValidUntrusted
        );
        assert_eq!(
            classify(false, "/tmp/x: code object is not signed at all\n"),
            SignState::Unsigned
        );
        assert_eq!(
            classify(true, "Authority=Apple Development: dev@example.com (ABC)\n"),
            SignState::ValidUntrusted
        );
    }
}
