use anyhow::{Context, Result, ensure};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::windows::process::CommandExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use whohack_core::{Config, local_session::LocalSession};

const HIDDEN: u32 = 0x08000000;

#[derive(Debug)]
struct Layout {
    root: PathBuf,
    local: PathBuf,
    config: PathBuf,
    session: PathBuf,
}
impl Layout {
    fn new(root: PathBuf) -> Result<Self> {
        let root = root.canonicalize()?;
        let local = root.join(".vigil/windows");
        fs::create_dir_all(&local)?;
        Ok(Self {
            config: local.join("config.toml"),
            session: local.join("session"),
            root,
            local,
        })
    }
    fn binary(&self, name: &str) -> Result<PathBuf> {
        let packaged = self.root.join("bin").join(format!("{name}.exe"));
        if packaged.is_file() {
            return Ok(packaged);
        }
        let base = if name == "whohack-tray" {
            self.root.join("ui/src-tauri")
        } else {
            self.root.clone()
        };
        let profile = if std::env::current_exe()?
            .parent()
            .and_then(Path::file_name)
            .is_some_and(|name| name == "release")
        {
            "release"
        } else {
            "debug"
        };
        let path = base
            .join("target")
            .join(profile)
            .join(format!("{name}.exe"));
        ensure!(
            path.is_file(),
            "Missing {}. Build the project or extract the complete package.",
            path.display()
        );
        Ok(path)
    }
    fn lock(&self, name: &str) -> Result<File> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.local.join(name))?;
        file.try_lock()
            .context("another whohack launcher operation is still active")?;
        Ok(file)
    }
    fn service_command(&self, argument: &str) -> Result<()> {
        let log = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.local.join("launcher.log"))?;
        let mut child = Command::new(self.binary("whohack-service")?)
            .args(["--config"])
            .arg(&self.config)
            .arg(argument)
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log)
            .creation_flags(HIDDEN)
            .spawn()?;
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = child.try_wait()? {
                ensure!(
                    status.success(),
                    "{argument} failed. See {}",
                    self.local.join("launcher.log").display()
                );
                return Ok(());
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                anyhow::bail!("{argument} timed out");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    fn prepare(&self) -> Result<Config> {
        crate::package::verify(&self.root)?;
        if !self.config.exists() {
            let rules = self.local.join("rules");
            copy_rules(&self.root.join("rules"), &rules, 0, &mut 0)?;
            let mut cfg = Config {
                mode: whohack_core::ResponseMode::Monitor,
                ..Default::default()
            };
            cfg.paths.data_dir = self.local.join("data");
            cfg.paths.log_dir = self.local.join("logs");
            cfg.paths.rules_dir = rules;
            cfg.collect.backend = whohack_core::config::CollectBackend::Poll;
            cfg.collect.dns = false;
            cfg.ipc.endpoint = format!(r"\\.\pipe\whohack-preview-{:032x}", rand::random::<u128>());
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&self.config)?;
            file.write_all(cfg.to_toml_string()?.as_bytes())?;
            file.sync_all()?;
            self.service_command("--write-manifest")?;
        }
        self.service_command("--check-config")?;
        Config::load(&self.config).map_err(Into::into)
    }
    fn spawn(&self, name: &str, args: &[&str]) -> Result<Child> {
        let log = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.local.join(format!("{name}-launch.log")))?;
        Ok(Command::new(self.binary(name)?)
            .args(args)
            .current_dir(&self.root)
            .env("WHOHACK_CONFIG", &self.config)
            .env("WHOHACK_SESSION_FILE", &self.session)
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log)
            .creation_flags(HIDDEN)
            .spawn()?)
    }
    fn write_health(&self, state: &str, message: &str) {
        let _ = fs::write(
            self.local.join("launcher-health.json"),
            serde_json::json!({"timestamp": whohack_core::time::now_ms(), "state": state, "message": message})
                .to_string(),
        );
    }
    fn write_running(&self, status: &whohack_ipc::StatusInfo) {
        if status.integrity_issues.is_empty() {
            self.write_health("running", "whohack is monitoring Windows");
        } else {
            self.write_health(
                "degraded",
                "whohack is running with integrity issues; inspect status",
            );
        }
    }
}

fn copy_rules(from: &Path, to: &Path, depth: usize, count: &mut usize) -> Result<()> {
    ensure!(
        depth <= 16 && *count <= 4096,
        "rules tree exceeds package limits"
    );
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        *count += 1;
        ensure!(
            *count <= 4096 && !entry.file_type()?.is_symlink(),
            "invalid rules tree"
        );
        if entry.file_name() == "MANIFEST.sha256" {
            continue;
        }
        let dest = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_rules(&entry.path(), &dest, depth + 1, count)?;
        } else {
            ensure!(
                entry.file_type()?.is_file() && entry.metadata()?.len() <= 8 * 1024 * 1024,
                "invalid rules file"
            );
            fs::copy(entry.path(), dest)?;
        }
    }
    Ok(())
}

async fn status(cfg: &Config) -> Option<Box<whohack_ipc::StatusInfo>> {
    tokio::time::timeout(Duration::from_secs(2), async {
        let token =
            whohack_ipc::auth::read_token_file(&cfg.paths.data_dir.join("ipc.token")).ok()?;
        let stream = whohack_ipc::transport::connect(&cfg.ipc.endpoint)
            .await
            .ok()?;
        let mut client = whohack_ipc::Client::connect(stream, &token).await.ok()?;
        match client.request(whohack_ipc::Request::Status).await.ok()? {
            whohack_ipc::Response::Status { status } => Some(status),
            _ => None,
        }
    })
    .await
    .ok()
    .flatten()
}

async fn start(layout: &Layout, tray: bool) -> Result<()> {
    let _lock = layout.lock("launcher.lock")?;
    if tray {
        layout.binary("whohack-tray")?;
    }
    let cfg = layout.prepare()?;
    let mut ready = status(&cfg).await;
    ensure!(
        ready.as_ref().is_none_or(|s| s.download_activity_available),
        "An older Vigil/whohack service is still running. To apply the new name and download view, right-click Update whohack.cmd and choose Run as administrator. This preserves your configuration and saved data."
    );
    if ready.is_none() {
        // A running, unresponsive session must be inspected, never duplicated.
        if let Ok(lock) = OpenOptions::new()
            .read(true)
            .write(true)
            .open(cfg.paths.data_dir.join("service.lock"))
        {
            lock.try_lock().context("The existing service is not answering. Stop it and inspect the log before retrying.")?;
        }
        let id = format!("{:032x}", rand::random::<u128>());
        fs::write(&layout.session, &id)?;
        let mut watchdog = Command::new(std::env::current_exe()?)
            .arg("watch")
            .arg("--root")
            .arg(&layout.root)
            .arg("--session-id")
            .arg(&id)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(HIDDEN)
            .spawn()?;
        let deadline = Instant::now() + Duration::from_secs(35);
        while ready.is_none() {
            if let Some(code) = watchdog.try_wait()? {
                anyhow::bail!(
                    "whohack supervisor exited ({code}). See {}",
                    layout.local.display()
                );
            }
            ensure!(
                Instant::now() < deadline,
                "whohack did not become ready. See {}",
                layout.local.display()
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
            ready = status(&cfg).await;
        }
    } else {
        ensure!(
            layout.session.is_file(),
            "This service was started separately; this launcher does not own it"
        );
    }
    ensure!(
        ready
            .as_ref()
            .is_some_and(|s| s.collectors.iter().any(|n| n.starts_with("windows-"))),
        "The service is not monitoring Windows"
    );
    if tray {
        // Existing tray observes this request, so double-click also reopens it.
        fs::write(
            layout.session.with_extension("show"),
            format!("{:032x}", rand::random::<u128>()),
        )?;
        let mut child = layout.spawn("whohack-tray", &["--show"])?;
        tokio::time::sleep(Duration::from_millis(800)).await;
        ensure!(
            child.try_wait()?.is_none_or(|s| s.success()),
            "The tray could not start. See its launch log."
        );
    }
    layout.write_running(ready.as_ref().unwrap());
    println!(
        "whohack is monitoring Windows. Automatic response is off in the default configuration."
    );
    Ok(())
}

async fn stop(layout: &Layout) -> Result<()> {
    let _lock = layout.lock("launcher.lock")?;
    if !layout.session.exists() {
        layout.write_health("stopped", "No launcher-owned session is running");
        println!("No launcher-owned session is running.");
        return Ok(());
    }
    // Removing the owned session marker must work even if configuration was
    // damaged. The supervisor lock remains held until its exact child exits.
    let data_dir = Config::load(&layout.config)
        .map(|cfg| cfg.paths.data_dir)
        .unwrap_or_else(|_| layout.local.join("data"));
    fs::remove_file(&layout.session)?;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let all_stopped = [
            data_dir.join("service.lock"),
            layout.session.with_extension("tray.lock"),
            layout.local.join("watchdog.lock"),
        ]
        .iter()
        .all(|p| {
            if !p.exists() {
                return true;
            }
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(p)
                .is_ok_and(|f| f.try_lock().is_ok())
        });
        if all_stopped {
            layout.write_health("stopped", "Stopped this Windows whohack session");
            println!("Stopped this Windows whohack session.");
            return Ok(());
        }
        ensure!(
            Instant::now() < deadline,
            "whohack is still draining accepted events. Check its log; no process was forcibly terminated."
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

async fn watch(layout: &Layout, id: &str) -> Result<()> {
    let _lock = layout.lock("watchdog.lock")?;
    ensure!(
        fs::read_to_string(&layout.session)? == id,
        "launcher session was replaced"
    );
    let session = LocalSession::open(&layout.session)?;
    let mut failures = 0;
    let mut window = Instant::now();
    while session.is_active() {
        crate::package::verify(&layout.root)?;
        let config = Config::load(&layout.config)?;
        let cfg = layout.config.to_string_lossy();
        let marker = layout.session.to_string_lossy();
        let mut child = layout.spawn(
            "whohack-service",
            &["--config", &cfg, "--run", "--session-file", &marker],
        )?;
        let mut next_probe = Instant::now();
        let mut confirmed = false;
        loop {
            if let Some(code) = child.try_wait()? {
                if !session.is_active() {
                    return Ok(());
                }
                layout.write_health(
                    "restarting",
                    &format!("Service exited ({code}); restart requested"),
                );
                break;
            }
            if !confirmed && Instant::now() >= next_probe && session.is_active() {
                if let Some(ready) = status(&config).await
                    && ready.service_pid == child.id()
                {
                    layout.write_running(&ready);
                    confirmed = true;
                }
                next_probe = Instant::now() + Duration::from_secs(1);
            }
            // Removal of the marker asks the owned service to flush and exit.
            // Retain its handle until it does; never kill a PID from a state file.
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        if window.elapsed() > Duration::from_secs(300) {
            failures = 0;
            window = Instant::now();
        }
        failures += 1;
        ensure!(
            failures <= 3,
            "Service repeatedly exited; automatic restarts stopped. Inspect whohack-service-launch.log."
        );
        tokio::time::sleep(Duration::from_secs(1 << failures)).await;
    }
    Ok(())
}

pub fn run() -> Result<()> {
    isolate_standard_handles()?;
    let mut args = std::env::args().skip(1);
    let action = args.next().unwrap_or_else(|| "start".into());
    let mut root = None;
    let mut id = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--root" => {
                root = Some(PathBuf::from(
                    args.next().context("--root requires a path")?,
                ))
            }
            "--session-id" => id = Some(args.next().context("session id missing")?),
            _ => anyhow::bail!("Unknown argument {arg}"),
        }
    }
    let root = root.unwrap_or_else(|| {
        let exe = std::env::current_exe().expect("current executable");
        let parent = exe.parent().unwrap();
        if parent.join("bin/whohack-service.exe").exists() {
            parent.into()
        } else {
            // Locate a source checkout from the Windows executable itself. A
            // cross-build embeds a Linux CARGO_MANIFEST_DIR which is not a valid
            // runtime location on Windows. Explicit --root supports other layouts.
            parent
                .ancestors()
                .find(|candidate| {
                    candidate.join("Cargo.toml").is_file()
                        && candidate.join("crates/whohack-launcher").is_dir()
                })
                .unwrap_or(parent)
                .to_path_buf()
        }
    });
    if action == "stop" && !root.exists() {
        println!("No launcher-owned session is running.");
        return Ok(());
    }
    let layout = Layout::new(root)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(async {
        match action.as_str() {
            "start" => start(&layout, true).await,
            "start-service" => start(&layout, false).await,
            "stop" => stop(&layout).await,
            "status" => {
                let cfg = Config::load(&layout.config)?;
                let status = status(&cfg)
                    .await
                    .context("Windows whohack is not responding")?;
                layout.write_running(&status);
                println!("{}", serde_json::to_string_pretty(&status)?);
                Ok(())
            }
            "watch" => watch(&layout, &id.context("watch requires a session id")?).await,
            _ => anyhow::bail!(
                "Use start, start-service, status or stop. Build source with Start whohack.cmd build."
            ),
        }
    });
    if let Err(error) = &result {
        layout.write_health("error", &format!("{error:#}"));
    }
    result
}

/// A caller may capture this command's output in inheritable pipes. Long-lived
/// descendants must not keep those unrelated pipe handles open after we return.
fn isolate_standard_handles() -> Result<()> {
    use windows_sys::Win32::{
        Foundation::{HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, SetHandleInformation},
        System::Console::{GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE},
    };
    for kind in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        // SAFETY: these borrowed handles belong to this process. Only the inherit
        // flag changes; the handle remains open for this launcher's output.
        #[allow(unsafe_code)]
        unsafe {
            let handle = GetStdHandle(kind);
            if !handle.is_null()
                && handle != INVALID_HANDLE_VALUE
                && SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) == 0
            {
                return Err(std::io::Error::last_os_error())
                    .context("isolate launcher output handles");
            }
        }
    }
    Ok(())
}

pub fn show_error(message: &str) {
    let message: Vec<u16> = message.encode_utf16().chain([0]).collect();
    let title: Vec<u16> = "whohack".encode_utf16().chain([0]).collect();
    // SAFETY: both NUL-terminated strings live through the modal call.
    #[allow(unsafe_code)]
    unsafe {
        windows_sys::Win32::UI::WindowsAndMessaging::MessageBoxW(
            std::ptr::null_mut(),
            message.as_ptr(),
            title.as_ptr(),
            windows_sys::Win32::UI::WindowsAndMessaging::MB_OK
                | windows_sys::Win32::UI::WindowsAndMessaging::MB_ICONERROR,
        );
    }
}
