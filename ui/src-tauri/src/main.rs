//! whohack tray app: a tray icon (open, mode, quit), a window with alerts,
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
use whohack_core::ResponseMode;
use whohack_ipc::{PushEvent, Request};

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
                        "whohack://connection",
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
                                .title(if alert.action == whohack_core::Action::SuspendAndAsk {
                                    "whohack paused suspicious activity".into()
                                } else {
                                    format!("whohack: {}", alert.app_name)
                                })
                                .body(&alert.explanation)
                                .show();
                        }
                        if let PushEvent::FolderScanFinished { message, .. } = &event {
                            let _ = app
                                .notification()
                                .builder()
                                .title("whohack folder check")
                                .body(message)
                                .show();
                        }
                        let _ = app.emit("whohack://push", &event);
                    }
                }
                let _ = app.emit(
                    "whohack://connection",
                    Connection {
                        connected: false,
                        message: "connection to the whohack service was lost".into(),
                    },
                );
            }
            Err(message) => {
                let _ = app.emit(
                    "whohack://connection",
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
                .title("whohack")
                .body(format!("Could not change mode: {e}"))
                .show();
        }
    });
}

fn main() {
    let settings = Settings::load();
    let context = tauri::generate_context!();
    // Build Windows webviews after the session lock, with an explicit profile
    // directory. The pinned Tauri runtime does not propagate dataDirectory from
    // WindowConfig into WebviewAttributes; use the builder API below.
    #[cfg(windows)]
    let (context, windows) = {
        let mut context = context;
        let windows = std::mem::take(&mut context.config_mut().app.windows);
        (context, windows)
    };
    tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .manage(Conn::new(settings.clone()))
        .invoke_handler(tauri::generate_handler![
            commands::status,
            commands::downloads,
            commands::folder_scan_status,
            commands::start_folder_scan,
            commands::stop_folder_scan,
            commands::alerts,
            commands::decision_details,
            commands::events,
            commands::resolve,
            commands::set_mode,
            commands::allowlist,
            commands::allow,
            commands::disallow,
            commands::profiles,
            commands::set_category,
            commands::responses,
            commands::release_response,
            commands::restore_quarantine,
        ])
        .setup(move |app| {
            if let Some(path) = std::env::var_os("WHOHACK_SESSION_FILE")
                .or_else(|| std::env::var_os("VIGIL_SESSION_FILE"))
            {
                let path = std::path::PathBuf::from(path);
                let session = whohack_core::local_session::LocalSession::open(&path)?;
                // Only one tray for this launcher's session. Release on exit.
                let lock = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(false)
                    .open(path.with_extension("tray.lock"))?;
                if lock.try_lock().is_err() {
                    if std::env::args().any(|arg| arg == "--show") {
                        let _ = std::fs::write(
                            path.with_extension("show"),
                            whohack_core::time::now_ms().to_string(),
                        );
                    }
                    app.handle().exit(0);
                    return Ok(());
                }
                let handle = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    let _lock = lock;
                    let request = path.with_extension("show");
                    let mut last = std::fs::read_to_string(&request).ok();
                    while session.is_active() {
                        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                        let current = std::fs::read_to_string(&request).ok();
                        if current.is_some() && current != last {
                            show_main(&handle);
                        }
                        last = current;
                    }
                    handle.exit(0);
                });
            }
            #[cfg(windows)]
            for config in windows.iter().filter(|window| window.create) {
                let data = settings
                    .token_file
                    .parent()
                    .ok_or_else(|| std::io::Error::other("whohack data directory is missing"))?;
                tauri::WebviewWindowBuilder::from_config(app.handle(), config)?
                    .data_directory(data.join("webview"))
                    .build()?;
            }
            let open = MenuItem::with_id(app, "open", "Open whohack", true, None::<&str>)?;
            let monitor =
                MenuItem::with_id(app, "mode_monitor", "Monitor only", true, None::<&str>)?;
            let prompt = MenuItem::with_id(
                app,
                "mode_prompt",
                "Prompt before stronger actions",
                false,
                None::<&str>,
            )?;
            let auto =
                MenuItem::with_id(app, "mode_auto", "Automatic response", false, None::<&str>)?;
            let modes =
                Submenu::with_items(app, "Protection mode", true, &[&monitor, &prompt, &auto])?;
            let quit = MenuItem::with_id(app, "quit", "Quit tray app", true, None::<&str>)?;
            let sep = PredefinedMenuItem::separator(app)?;
            let menu = Menu::with_items(app, &[&open, &modes, &sep, &quit])?;
            let mut tray = TrayIconBuilder::with_id("whohack")
                .tooltip("whohack")
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
            let mode_settings = settings.clone();
            tauri::async_runtime::spawn(async move {
                loop {
                    let available = async {
                        let mut client = mode_settings.open().await.ok()?;
                        match client.request(Request::Status).await.ok()? {
                            whohack_ipc::Response::Status { status } => Some(status),
                            _ => None,
                        }
                    };
                    let status = tokio::time::timeout(Duration::from_secs(2), available)
                        .await
                        .ok()
                        .flatten();
                    let _ = prompt.set_enabled(status.as_ref().is_some_and(|s| {
                        s.enforcement_available
                            || s.response_actions
                                .contains(&whohack_core::Action::SuspendAndAsk)
                    }));
                    let _ =
                        auto.set_enabled(status.as_ref().is_some_and(|s| {
                            s.enforcement_available && s.automatic_response_enabled
                        }));
                    tokio::time::sleep(Duration::from_secs(3)).await;
                }
            });
            if std::env::args().any(|arg| arg == "--show") {
                show_main(app.handle());
            }
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
        .run(context)
        .expect("error while running the whohack tray app");
}
