//! Messages exchanged between the service and the tray UI (SPEC §14).

use serde::{Deserialize, Serialize};
use vigil_core::{Action, AllowEntry, ResponseMode, VerdictLabel};

/// Bumped on any incompatible message change.
pub const PROTOCOL_VERSION: u32 = 1;

/// Client → service.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMsg {
    /// Must be the first message; carries the per-session token.
    Hello {
        token: String,
        version: u32,
    },
    Request {
        id: u64,
        request: Request,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    Status,
    /// Most recent alerts, newest first.
    ListAlerts {
        limit: u32,
    },
    /// The user's decision on an alert; stored as feedback.
    Resolve {
        alert_id: i64,
        action: Action,
        note: Option<String>,
    },
    SetMode {
        mode: ResponseMode,
    },
    ListAllowlist,
    Allow {
        entry: AllowEntry,
    },
    Disallow {
        entry: AllowEntry,
    },
    /// Start receiving `ServerMsg::Push` messages on this connection.
    Subscribe,
}

/// Service → client.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMsg {
    Welcome {
        version: u32,
        service_version: String,
    },
    Response {
        id: u64,
        response: Response,
    },
    Push {
        event: PushEvent,
    },
    /// Fatal for the connection (bad token, bad version, protocol error).
    Error {
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Response {
    Status { status: StatusInfo },
    Alerts { alerts: Vec<AlertSummary> },
    Allowlist { entries: Vec<AllowEntry> },
    Ok,
    Error { message: String },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StatusInfo {
    pub service_version: String,
    pub mode: ResponseMode,
    pub collectors: Vec<String>,
    pub dns_visible: bool,
    /// Decision model name, or `None` when only rules and scoring are active.
    pub model: Option<String>,
    pub model_loaded: bool,
    pub uptime_s: u64,
    pub events_seen: u64,
    pub open_alerts: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AlertSummary {
    pub id: i64,
    pub ts: i64,
    pub pid: u32,
    pub app_id: String,
    pub app_name: String,
    pub label: VerdictLabel,
    /// `[benign, suspicious, malicious]`.
    pub p: [f32; 3],
    pub severity: f32,
    pub action: Action,
    pub explanation: String,
    pub resolved: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum PushEvent {
    Alert {
        alert: AlertSummary,
    },
    ModeChanged {
        mode: ResponseMode,
    },
    /// Sent when protection is degraded (a collector stopped, a block was removed externally).
    Health {
        ok: bool,
        message: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_round_trip_with_tags() {
        let msgs = vec![
            ClientMsg::Hello {
                token: "t".into(),
                version: PROTOCOL_VERSION,
            },
            ClientMsg::Request {
                id: 1,
                request: Request::Status,
            },
            ClientMsg::Request {
                id: 2,
                request: Request::Resolve {
                    alert_id: 9,
                    action: Action::BlockNetwork,
                    note: None,
                },
            },
            ClientMsg::Request {
                id: 3,
                request: Request::Allow {
                    entry: AllowEntry::App { app_id: "a".into() },
                },
            },
        ];
        for m in msgs {
            let s = serde_json::to_string(&m).unwrap();
            assert_eq!(serde_json::from_str::<ClientMsg>(&s).unwrap(), m);
        }
        let v = serde_json::to_value(ClientMsg::Request {
            id: 7,
            request: Request::ListAlerts { limit: 5 },
        })
        .unwrap();
        assert_eq!(v["type"], "request");
        assert_eq!(v["request"]["op"], "list_alerts");
        let push = ServerMsg::Push {
            event: PushEvent::ModeChanged {
                mode: ResponseMode::Auto,
            },
        };
        let s = serde_json::to_string(&push).unwrap();
        assert_eq!(serde_json::from_str::<ServerMsg>(&s).unwrap(), push);
    }
}
