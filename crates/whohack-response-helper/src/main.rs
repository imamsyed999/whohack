#![cfg_attr(windows, windows_subsystem = "windows")]

fn main() -> std::process::ExitCode {
    #[cfg(windows)]
    {
        let args: Vec<_> = std::env::args().skip(1).collect();
        if args.len() == 1 && whohack_respond::run_windows_network_helper(&args[0]).is_ok() {
            return std::process::ExitCode::SUCCESS;
        }
    }
    std::process::ExitCode::FAILURE
}
