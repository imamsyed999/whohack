#![cfg_attr(all(windows, not(test)), windows_subsystem = "windows")]
#[cfg(any(windows, test))]
mod package;
#[cfg(windows)]
mod windows;

fn main() {
    #[cfg(windows)]
    if let Err(error) = windows::run() {
        let message = format!("whohack: {error:#}");
        eprintln!("{message}");
        // Double-click has no arguments. Explicit CLI actions must return an
        // error instead of waiting indefinitely for a modal desktop dialog.
        if std::env::args().nth(1).is_none() {
            windows::show_error(&message);
        }
        std::process::exit(1);
    }
    #[cfg(not(windows))]
    {
        eprintln!("This launcher runs natively on Windows. Use whohack-service on this OS.");
        std::process::exit(1);
    }
}
