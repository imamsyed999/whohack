use serde::{Deserialize, Serialize};

/// Operating system family Vigil runs on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Os {
    Windows,
    MacOs,
    Linux,
}

impl Os {
    /// The OS this binary was compiled for.
    pub const fn current() -> Os {
        if cfg!(target_os = "windows") {
            Os::Windows
        } else if cfg!(target_os = "macos") {
            Os::MacOs
        } else {
            Os::Linux
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_matches_target() {
        let os = Os::current();
        #[cfg(target_os = "windows")]
        assert_eq!(os, Os::Windows);
        #[cfg(target_os = "macos")]
        assert_eq!(os, Os::MacOs);
        #[cfg(target_os = "linux")]
        assert_eq!(os, Os::Linux);
    }

    #[test]
    fn serde_names() {
        assert_eq!(serde_json::to_string(&Os::MacOs).unwrap(), "\"mac_os\"");
    }
}
