//! Commands invoked by the web UI.

use tauri::State;
use whohack_core::{Action, AllowEntry, ResponseMode};
use whohack_ipc::{AlertSummary, EventSummary, Request, Response, StatusInfo};

use crate::conn::Conn;

#[tauri::command]
pub async fn decision_details(conn: State<'_, Conn>, alert_id: i64) -> Result<Response, String> {
    conn.call(Request::DecisionDetails { alert_id }).await
}

#[tauri::command]
pub async fn responses(conn: State<'_, Conn>) -> Result<Response, String> {
    conn.call(Request::ListResponses).await
}

#[tauri::command]
pub async fn release_response(conn: State<'_, Conn>, id: String) -> Result<(), String> {
    conn.call(Request::ReleaseResponse { id }).await.map(|_| ())
}

#[tauri::command]
pub async fn restore_quarantine(conn: State<'_, Conn>, id: String) -> Result<(), String> {
    conn.call(Request::RestoreQuarantine { id })
        .await
        .map(|_| ())
}

#[tauri::command]
pub async fn profiles(conn: State<'_, Conn>) -> Result<Response, String> {
    conn.call(Request::ListProfiles { limit: 500 }).await
}

#[tauri::command]
pub async fn set_category(
    conn: State<'_, Conn>,
    app_id: String,
    category: String,
) -> Result<(), String> {
    conn.call(Request::SetCategory { app_id, category })
        .await
        .map(|_| ())
}

fn unexpected(r: Response) -> String {
    format!("unexpected response from service: {r:?}")
}

#[tauri::command]
pub async fn status(conn: State<'_, Conn>) -> Result<StatusInfo, String> {
    match conn.call(Request::Status).await? {
        Response::Status { status } => Ok(*status),
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
