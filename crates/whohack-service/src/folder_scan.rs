//! Optional Windows Defender custom scans, off the runtime detection thread.
//! No shell, model download, execution of input content, or global AV settings.
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::broadcast;
use whohack_ipc::{FolderScanState, FolderScanSummary, PushEvent, Response};

const MAX_OUTPUT: usize = 64 * 1024;
const MAX_WAIT: Duration = Duration::from_secs(10 * 60);
const STOP_NOTE: &str = "The whohack scan client stopped. Windows Defender may finish work already submitted; check Windows Security before starting another scan.";
const LIMITATION: &str = "Optional static check using installed Microsoft Defender. Runtime protection continues separately. Report-only checks scan archives and ignore file exclusions; detections appear in this report rather than Windows Security history. Windows controls signature freshness and cloud/sample submission settings. A completed check is not a guarantee that files are safe. CPU throttling is requested at 25%; Windows controls actual usage. One check at a time; whohack requests a stop after 10 minutes.";

#[derive(Debug)]
struct Job {
    summary: FolderScanSummary,
    started: Instant,
    cancel: Arc<AtomicBool>,
}

#[derive(Debug, Default)]
struct Current {
    next_id: u64,
    job: Option<Job>,
}

#[derive(Debug)]
pub struct FolderScans {
    engine: Option<PathBuf>,
    current: Arc<Mutex<Current>>,
}

impl Default for FolderScans {
    fn default() -> Self {
        Self {
            engine: defender_path(),
            current: Arc::default(),
        }
    }
}

impl FolderScans {
    pub fn available(&self) -> bool {
        self.engine.is_some()
    }

    pub fn status(&self) -> Result<Response, String> {
        let current = self
            .current
            .lock()
            .map_err(|_| "Folder check state unavailable")?;
        let scan = current.job.as_ref().map(|job| {
            let mut summary = job.summary.clone();
            if summary.state == FolderScanState::Running {
                summary.elapsed_s = job.started.elapsed().as_secs();
            }
            summary
        });
        Ok(Response::FolderScan {
            available: self.engine.is_some(),
            limitation: if self.engine.is_some() {
                LIMITATION.into()
            } else {
                "Microsoft Defender command-line scanner was not found. This optional check requires Windows with Defender available. Runtime monitoring is separate.".into()
            },
            scan,
        })
    }

    pub fn start(
        &self,
        path: String,
        remediate: bool,
        pushes: broadcast::Sender<PushEvent>,
    ) -> Result<Response, String> {
        let path = validate_folder(&path)?;
        let engine = self
            .engine
            .clone()
            .ok_or("Microsoft Defender is unavailable")?;
        let mut current = self
            .current
            .lock()
            .map_err(|_| "Folder check state unavailable")?;
        if current
            .job
            .as_ref()
            .is_some_and(|j| j.summary.state == FolderScanState::Running)
        {
            return Err("A folder check is already running".into());
        }
        current.next_id += 1;
        let id = current.next_id;
        let cancel = Arc::new(AtomicBool::new(false));
        current.job = Some(Job {
            summary: FolderScanSummary {
                id,
                path: path.to_string_lossy().into(),
                engine: engine.to_string_lossy().into(),
                remediate,
                state: FolderScanState::Running,
                started_at: whohack_core::time::now_ms(),
                finished_at: None,
                elapsed_s: 0,
                exit_code: None,
                output: String::new(),
                output_truncated: false,
                message: "Checking the selected folder and its contents. Windows does not provide a file count or percentage through this interface.".into(),
            },
            started: Instant::now(),
            cancel: cancel.clone(),
        });
        let shared = self.current.clone();
        if let Err(e) = std::thread::Builder::new()
            .name("whohack-folder-check".into())
            .spawn(move || {
                let outcome = run(&engine, &path, remediate, &cancel);
                if let Ok(mut current) = shared.lock()
                    && let Some(job) = &mut current.job
                    && job.summary.id == id
                {
                    let (state, exit_code, output, truncated, message) =
                        outcome.unwrap_or_else(|e| {
                            (FolderScanState::Failed, None, String::new(), false, e)
                        });
                    job.summary.state = state;
                    job.summary.exit_code = exit_code;
                    job.summary.output = output;
                    job.summary.output_truncated = truncated;
                    job.summary.message = message.clone();
                    job.summary.elapsed_s = job.started.elapsed().as_secs();
                    job.summary.finished_at = Some(whohack_core::time::now_ms());
                    let _ = pushes.send(PushEvent::FolderScanFinished { id, message });
                }
            })
        {
            current.job = None;
            return Err(format!("Could not start folder check: {e}"));
        }
        drop(current);
        self.status()
    }

    pub fn stop(&self, id: u64) -> Result<Response, String> {
        let current = self
            .current
            .lock()
            .map_err(|_| "Folder check state unavailable")?;
        let job = current
            .job
            .as_ref()
            .filter(|j| j.summary.id == id)
            .ok_or("That folder check is no longer the current job")?;
        if job.summary.state == FolderScanState::Running {
            job.cancel.store(true, Ordering::Relaxed);
        }
        drop(current);
        self.status()
    }

    pub fn shutdown(&self) {
        if let Ok(current) = self.current.lock()
            && let Some(job) = &current.job
        {
            job.cancel.store(true, Ordering::Relaxed);
        }
    }
}

impl Drop for FolderScans {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn validate_folder(text: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(text);
    if !whohack_taint::downloads::local_path(&path) || !path.is_dir() || path.parent().is_none() {
        return Err("Choose an existing absolute local folder, not a drive root, network/device path, parent traversal or linked/cloud folder.".into());
    }
    Ok(path)
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn known_folder(id: &windows_sys::core::GUID) -> Option<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::Com::{
        COINIT_MULTITHREADED, CoInitializeEx, CoTaskMemFree, CoUninitialize,
    };
    use windows_sys::Win32::UI::Shell::SHGetKnownFolderPath;
    // SAFETY: COM initialization is balanced when this call adds a reference.
    // SHGetKnownFolderPath owns its terminated UTF-16 allocation until freed.
    unsafe {
        let initialized = CoInitializeEx(std::ptr::null(), COINIT_MULTITHREADED as u32);
        if initialized < 0 && initialized != 0x80010106_u32 as i32 {
            return None;
        }
        let mut raw = std::ptr::null_mut();
        let result = SHGetKnownFolderPath(id, 0, std::ptr::null_mut(), &mut raw);
        let path = if result >= 0 && !raw.is_null() {
            let mut len = 0;
            while *raw.add(len) != 0 {
                len += 1;
            }
            Some(PathBuf::from(std::ffi::OsString::from_wide(
                std::slice::from_raw_parts(raw, len),
            )))
        } else {
            None
        };
        CoTaskMemFree(raw.cast());
        if initialized >= 0 {
            CoUninitialize();
        }
        path
    }
}

#[cfg(windows)]
fn defender_path() -> Option<PathBuf> {
    use windows_sys::Win32::UI::Shell::{FOLDERID_ProgramData, FOLDERID_ProgramFiles};
    let mut candidates = Vec::new();
    if let Some(data) = known_folder(&FOLDERID_ProgramData) {
        let platform = data.join("Microsoft/Windows Defender/Platform");
        if whohack_taint::downloads::local_path(&platform)
            && let Ok(entries) = std::fs::read_dir(platform)
        {
            for entry in entries.take(128).flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if name
                    .bytes()
                    .all(|b| b.is_ascii_digit() || matches!(b, b'.' | b'-'))
                {
                    let version: Vec<u64> = name
                        .split(['.', '-'])
                        .filter_map(|n| n.parse().ok())
                        .collect();
                    if version.len() >= 4 {
                        candidates.push((version, entry.path().join("MpCmdRun.exe")));
                    }
                }
            }
        }
    }
    candidates.sort_by(|a, b| b.0.cmp(&a.0));
    if let Some(programs) = known_folder(&FOLDERID_ProgramFiles) {
        candidates.push((vec![], programs.join("Windows Defender/MpCmdRun.exe")));
    }
    candidates
        .into_iter()
        .map(|(_, p)| p)
        .find(|p| whohack_taint::downloads::local_path(p) && p.is_file())
}

#[cfg(not(windows))]
fn defender_path() -> Option<PathBuf> {
    None
}

fn scan_command(engine: &Path, path: &Path, remediate: bool) -> Command {
    let mut command = Command::new(engine);
    command.args(["-Scan", "-ScanType", "3", "-File"]).arg(path);
    if !remediate {
        command.arg("-DisableRemediation");
    }
    command
        .args(["-CpuThrottling", "25"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }
    command
}

/// Drain every byte to prevent pipe deadlocks, retaining at most MAX_OUTPUT.
fn capture(mut reader: impl Read) -> (Vec<u8>, bool) {
    let mut output = Vec::new();
    let mut buffer = [0; 4096];
    let mut truncated = false;
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => {
                let keep = n.min(MAX_OUTPUT - output.len());
                output.extend_from_slice(&buffer[..keep]);
                truncated |= keep != n;
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => {
                truncated = true;
                break;
            }
        }
    }
    (output, truncated)
}

fn exit_result(code: Option<i32>, remediate: bool) -> (FolderScanState, String) {
    match code {
        Some(0) => (FolderScanState::Completed, if remediate {
            "Defender completed the scan and any configured remediation. Review the report and Windows Security protection history for actions."
        } else {
            "Defender completed the report-only check. Review the report below. No threat reported does not prove that a file is safe."
        }.into()),
        Some(2) => (FolderScanState::ReviewRequired, "Defender returned 2: threats may need attention, or a scan error occurred. Review the report; this code alone is not proof of malware.".into()),
        code => (FolderScanState::Failed, format!("Defender did not complete successfully (exit {code:?}). Protection may be disabled or access denied; review the report.")),
    }
}

type Outcome = (FolderScanState, Option<i32>, String, bool, String);

fn run(
    engine: &Path,
    path: &Path,
    remediate: bool,
    cancel: &AtomicBool,
) -> Result<Outcome, String> {
    #[cfg(windows)]
    {
        // Revalidate the known-folder selection immediately before verification.
        if defender_path().as_deref() != Some(engine) {
            return Err(
                "The installed Defender scanner changed; restart whohack before retrying".into(),
            );
        }
        let trusted = whohack_taint::sign::SignChecker::new().check(engine).state;
        if !matches!(trusted, whohack_core::SignState::ValidTrusted { publisher }
            if matches!(publisher.as_str(), "Microsoft Windows" | "Microsoft Windows Publisher" | "Microsoft Corporation"))
        {
            return Err("The installed scanner's Microsoft signature could not be verified".into());
        }
    }
    validate_folder(&path.to_string_lossy())?;
    if cancel.load(Ordering::Relaxed) {
        return Ok((
            FolderScanState::Stopped,
            None,
            String::new(),
            false,
            "Folder check stopped before launch.".into(),
        ));
    }
    let mut child = scan_command(engine, path, remediate)
        .spawn()
        .map_err(|e| format!("Could not start Microsoft Defender: {e}"))?;
    let stdout = child.stdout.take().ok_or("Missing scanner output pipe")?;
    let stderr = child.stderr.take().ok_or("Missing scanner error pipe")?;
    let started = Instant::now();
    std::thread::scope(|scope| {
        let out = scope.spawn(|| capture(stdout));
        let err = scope.spawn(|| capture(stderr));
        let mut forced = None;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Ok(status),
                Ok(None) => {}
                Err(e) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break Err(format!("Could not read scanner completion: {e}"));
                }
            }
            if cancel.load(Ordering::Relaxed) || started.elapsed() >= MAX_WAIT {
                forced = Some(if cancel.load(Ordering::Relaxed) {
                    FolderScanState::Stopped
                } else {
                    FolderScanState::TimedOut
                });
                // Only this owned client, never MpCmdRun -Cancel (which targets
                // other quick/full scans). The engine service is not terminated.
                let killed = child.kill();
                if let Err(e) = killed {
                    // Retain ownership until exit instead of spawning another
                    // job while an untracked scanner may still be running.
                    tracing::warn!(error = %e, "could not stop owned Defender client");
                }
                break child
                    .wait()
                    .map_err(|e| format!("Scanner client wait failed: {e}"));
            }
            std::thread::sleep(Duration::from_millis(100));
        }?;
        let (stdout, a) = out.join().map_err(|_| "Scanner output reader failed")?;
        let (stderr, b) = err.join().map_err(|_| "Scanner error reader failed")?;
        let output = format!(
            "{}{}",
            String::from_utf8_lossy(&stdout),
            String::from_utf8_lossy(&stderr)
        );
        let (state, message) = forced
            .map(|s| (s, STOP_NOTE.into()))
            .unwrap_or_else(|| exit_result(status.code(), remediate));
        Ok((state, status.code(), output, a || b, message))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_folder_required_and_parent_traversal_refused() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("folder with spaces & quotes");
        std::fs::create_dir(&path).unwrap();
        assert_eq!(validate_folder(&path.to_string_lossy()).unwrap(), path);
        std::fs::write(temp.path().join("file"), b"harmless").unwrap();
        for value in [
            "relative".into(),
            temp.path().join("file").to_string_lossy().into_owned(),
            temp.path().join("missing").to_string_lossy().into_owned(),
            path.join("..").to_string_lossy().into_owned(),
        ] {
            assert!(validate_folder(&value).is_err(), "{value}");
        }
        #[cfg(windows)]
        for value in [
            r"C:\",
            r"\\localhost\c$\Users",
            r"\\?\C:\Users",
            r"C:\Users:stream",
            "C:\\Users\n",
        ] {
            assert!(validate_folder(value).is_err(), "{value}");
        }
    }

    #[test]
    fn command_uses_one_literal_path_and_report_only_is_default() {
        let path = Path::new(r#"C:\Downloads\quotes & $() with spaces"#);
        let command = scan_command(Path::new("MpCmdRun.exe"), path, false);
        let args: Vec<_> = command.get_args().collect();
        assert_eq!(args[4], path.as_os_str());
        assert!(args.contains(&std::ffi::OsStr::new("-DisableRemediation")));
        assert!(
            !scan_command(Path::new("MpCmdRun.exe"), path, true)
                .get_args()
                .any(|a| a == "-DisableRemediation")
        );
    }

    #[test]
    fn output_is_bounded_and_drained_and_ambiguous_exit_is_not_malware_verdict() {
        let bytes = vec![b'x'; MAX_OUTPUT + 100];
        let mut reader = bytes.as_slice();
        let (out, truncated) = capture(&mut reader);
        assert_eq!(out.len(), MAX_OUTPUT);
        assert!(truncated && reader.is_empty());
        assert_eq!(
            exit_result(Some(2), false).0,
            FolderScanState::ReviewRequired
        );
        assert_eq!(exit_result(Some(0), false).0, FolderScanState::Completed);
        assert_eq!(exit_result(Some(5), false).0, FolderScanState::Failed);
        assert!(exit_result(Some(0), true).1.contains("remediation"));
    }

    #[test]
    fn active_job_cannot_be_replaced_and_stale_id_cannot_stop_it() {
        let temp = tempfile::tempdir().unwrap();
        let scans = FolderScans {
            engine: Some(PathBuf::from("never-executed")),
            current: Arc::default(),
        };
        let cancel = Arc::new(AtomicBool::new(false));
        scans.current.lock().unwrap().job = Some(Job {
            started: Instant::now(),
            cancel: cancel.clone(),
            summary: FolderScanSummary {
                id: 9,
                path: temp.path().to_string_lossy().into(),
                engine: String::new(),
                remediate: false,
                state: FolderScanState::Running,
                started_at: 1,
                finished_at: None,
                elapsed_s: 0,
                exit_code: None,
                output: String::new(),
                output_truncated: false,
                message: String::new(),
            },
        });
        let (pushes, _) = broadcast::channel(8);
        assert!(
            scans
                .start(temp.path().to_string_lossy().into(), false, pushes)
                .unwrap_err()
                .contains("already running")
        );
        assert!(scans.stop(8).is_err());
        assert!(!cancel.load(Ordering::Relaxed));
        scans.stop(9).unwrap();
        assert!(cancel.load(Ordering::Relaxed));
    }
}
