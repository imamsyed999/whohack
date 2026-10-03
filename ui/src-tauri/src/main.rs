//! Vigil tray app: a tray icon (open, mode, quit), a window with alerts,
//! timeline, allowlist, and status, and desktop notifications for new alerts.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod conn;

use std::time::Duration;

use serde::Serialize;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem, Submenu};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, WindowEvent};
use tauri_plugin_notification::NotificationExt;
use vigil_core::ResponseMode;
use vigil_ipc::{PushEvent, Request};

use crate::conn::{Conn, Settings};

#[derive(Debug, Clone, Serialize)]
struct Connection {
    connected: bool,
    message: String,
}

fn show_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
    }
}

/// Keeps a subscribed connection open, forwarding pushes to the window and
/// raising notifications for new alerts. Reconnects with a short delay.
async fn push_loop(app: AppHandle, settings: Settings) {
    loop {
        match settings.open().await {
            Ok(mut client) => {
                if client.request(Request::Subscribe).await.is_ok() {
                    let _ = app.emit(
                        "vigil://connection",
                        Connection {
                            connected: true,
                            message: String::new(),
                        },
                    );
                    while let Ok(event) = client.next_push().await {
                        if let PushEvent::Alert { alert } = &event {
                            let _ = app
                                .notification()
                                .builder()
                                .title(format!("Vigil: {}", alert.app_name))
                                .body(&alert.explanation)
                                .show();
                        }
                        let _ = app.emit("vigil://push", &event);
                    }
                }
                let _ = app.emit(
                    "vigil://connection",
                    Connection {
                        connected: false,
                        message: "connection to the Vigil service was lost".into(),
                    },
                );
            }
            Err(message) => {
                let _ = app.emit(
                    "vigil://connection",
                    Connection {
                        connected: false,
                        message,
                    },
                );
            }
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

fn set_mode_from_tray(app: &AppHandle, mode: ResponseMode) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let conn = app.state::<Conn>();
        if let Err(e) = conn.call(Request::SetMode { mode }).await {
            let _ = app
                .notification()
                .builder()
                .title("Vigil")
                .body(format!("Could not change mode: {e}"))
                .show();
        }
    });
}

fn main() {
    let settings = Settings::load();
    tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .manage(Conn::new(settings.clone()))
        .invoke_handler(tauri::generate_handler![
            commands::status,
            commands::alerts,
            commands::events,
            commands::resolve,
            commands::set_mode,
            commands::allowlist,
            commands::allow,
            commands::disallow,
        ])
        .setup(move |app| {
            let open = MenuItem::with_id(app, "open", "Open Vigil", true, None::<&str>)?;
            let monitor =
                MenuItem::with_id(app, "mode_monitor", "Monitor only", true, None::<&str>)?;
            let prompt = MenuItem::with_id(
                app,
                "mode_prompt",
                "Prompt (recommended)",
                true,
                None::<&str>,
            )?;
            let auto = MenuItem::with_id(app, "mode_auto", "Automatic", true, None::<&str>)?;
            let modes =
                Submenu::with_items(app, "Protection mode", true, &[&monitor, &prompt, &auto])?;
            let quit = MenuItem::with_id(app, "quit", "Quit tray app", true, None::<&str>)?;
            let sep = PredefinedMenuItem::separator(app)?;
            let menu = Menu::with_items(app, &[&open, &modes, &sep, &quit])?;
            let mut tray = TrayIconBuilder::with_id("vigil")
                .tooltip("Vigil")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "open" => show_main(app),
                    "mode_monitor" => set_mode_from_tray(app, ResponseMode::Monitor),
                    "mode_prompt" => set_mode_from_tray(app, ResponseMode::Prompt),
                    "mode_auto" => set_mode_from_tray(app, ResponseMode::Auto),
                    "quit" => app.exit(0),
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        show_main(tray.app_handle());
                    }
                });
            if let Some(icon) = app.default_window_icon() {
                tray = tray.icon(icon.clone());
            }
            tray.build(app)?;
            tauri::async_runtime::spawn(push_loop(app.handle().clone(), settings.clone()));
            Ok(())
        })
        .on_window_event(|window, event| {
            // Closing the window keeps the tray app (and notifications) running.
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running the Vigil tray app");
}
