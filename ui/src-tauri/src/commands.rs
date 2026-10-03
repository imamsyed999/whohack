//! Commands invoked by the web UI.

use tauri::State;
use vigil_core::{Action, AllowEntry, ResponseMode};
use vigil_ipc::{AlertSummary, EventSummary, Request, Response, StatusInfo};

use crate::conn::Conn;

fn unexpected(r: Response) -> String {
    format!("unexpected response from service: {r:?}")
}

#[tauri::command]
pub async fn status(conn: State<'_, Conn>) -> Result<StatusInfo, String> {
    match conn.call(Request::Status).await? {
        Response::Status { status } => Ok(status),
        r => Err(unexpected(r)),
    }
}

#[tauri::command]
pub async fn alerts(conn: State<'_, Conn>, limit: u32) -> Result<Vec<AlertSummary>, String> {
    match conn.call(Request::ListAlerts { limit }).await? {
        Response::Alerts { alerts } => Ok(alerts),
        r => Err(unexpected(r)),
    }
}

#[tauri::command]
pub async fn events(conn: State<'_, Conn>, limit: u32) -> Result<Vec<EventSummary>, String> {
    match conn.call(Request::RecentEvents { limit }).await? {
        Response::Events { events } => Ok(events),
        r => Err(unexpected(r)),
    }
}

fn parse_action(s: &str) -> Result<Action, String> {
    Action::parse(s).ok_or_else(|| format!("unknown action {s:?}"))
}

#[tauri::command]
pub async fn resolve(
    conn: State<'_, Conn>,
    alert_id: i64,
    action: String,
    note: Option<String>,
) -> Result<(), String> {
    let action = parse_action(&action)?;
    conn.call(Request::Resolve {
        alert_id,
        action,
        note,
    })
    .await
    .map(|_| ())
}

#[tauri::command]
pub async fn set_mode(conn: State<'_, Conn>, mode: String) -> Result<(), String> {
    let mode = ResponseMode::parse(&mode).ok_or_else(|| format!("unknown mode {mode:?}"))?;
    conn.call(Request::SetMode { mode }).await.map(|_| ())
}

#[tauri::command]
pub async fn allowlist(conn: State<'_, Conn>) -> Result<Vec<AllowEntry>, String> {
    match conn.call(Request::ListAllowlist).await? {
        Response::Allowlist { entries } => Ok(entries),
        r => Err(unexpected(r)),
    }
}

#[tauri::command]
pub async fn allow(conn: State<'_, Conn>, entry: AllowEntry) -> Result<(), String> {
    conn.call(Request::Allow { entry }).await.map(|_| ())
}

#[tauri::command]
pub async fn disallow(conn: State<'_, Conn>, entry: AllowEntry) -> Result<(), String> {
    conn.call(Request::Disallow { entry }).await.map(|_| ())
}
