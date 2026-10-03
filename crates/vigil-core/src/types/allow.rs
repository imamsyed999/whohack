use serde::{Deserialize, Serialize};

/// A user trust decision (SPEC §11).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AllowEntry {
    /// Trust an application entirely (by signing id or sha256 — its `app_id`).
    App { app_id: String },
    /// Trust a network destination (IP, CIDR, or registrable domain) for all apps.
    Destination { value: String },
    /// Trust one capability tag for one app.
    Behavior { app_id: String, tag: String },
}

impl AllowEntry {
    /// `(kind, app_id, value)` as stored in the `allowlist` table. `app_id` is
    /// `""` for entries that are not app-scoped so the UNIQUE constraint works
    /// (SQLite treats NULLs as distinct).
    pub fn to_columns(&self) -> (&'static str, &str, &str) {
        match self {
            AllowEntry::App { app_id } => ("app", app_id, ""),
            AllowEntry::Destination { value } => ("destination", "", value),
            AllowEntry::Behavior { app_id, tag } => ("behavior", app_id, tag),
        }
    }

    /// Inverse of [`to_columns`](Self::to_columns). Returns `None` for an unknown kind.
    pub fn from_columns(kind: &str, app_id: String, value: String) -> Option<AllowEntry> {
        match kind {
            "app" => Some(AllowEntry::App { app_id }),
            "destination" => Some(AllowEntry::Destination { value }),
            "behavior" => Some(AllowEntry::Behavior { app_id, tag: value }),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn columns_round_trip() {
        let entries = [
            AllowEntry::App {
                app_id: "com.example.app".into(),
            },
            AllowEntry::Destination {
                value: "example.com".into(),
            },
            AllowEntry::Behavior {
                app_id: "abc".into(),
                tag: "network:unusual_port".into(),
            },
        ];
        for e in entries {
            let (k, a, v) = e.to_columns();
            assert_eq!(
                AllowEntry::from_columns(k, a.into(), v.into()),
                Some(e.clone())
            );
            let s = serde_json::to_string(&e).unwrap();
            assert_eq!(serde_json::from_str::<AllowEntry>(&s).unwrap(), e);
        }
        assert_eq!(
            AllowEntry::from_columns("bogus", String::new(), String::new()),
            None
        );
    }
}
