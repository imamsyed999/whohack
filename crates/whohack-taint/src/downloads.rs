//! Bounded local input attribution. Never fetch URLs or follow device/UNC paths.
use std::path::{Path, PathBuf};
use whohack_core::{DownloadedInput, Origin, PathClass};

use crate::{FileAnalyzer, origin, path_class, script};

pub const MAX_INPUTS: usize = 8;
const MAX_INPUT_SCAN_BYTES: u64 = 16 * 1024 * 1024;

/// Existing local path with no link/reparse ancestors. This is a best-effort
/// path check, not a handle-based authorization for deleting arbitrary files.
pub fn local_path(path: &Path) -> bool {
    let text = path.to_string_lossy();
    if !path.is_absolute()
        || text.len() > 4096
        || text.chars().any(char::is_control)
        || path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return false;
    }
    #[cfg(windows)]
    if text.starts_with(['\\', '/']) || text.get(2..).is_some_and(|s| s.contains(':')) {
        return false;
    }
    #[cfg(windows)]
    {
        // Do not turn a mapped network drive into an implicit remote scan.
        use windows_sys::Win32::Storage::FileSystem::GetDriveTypeW;
        let Some(drive) = text.get(..2) else {
            return false;
        };
        let root: Vec<u16> = format!("{drive}\\").encode_utf16().chain([0]).collect();
        // SAFETY: a valid NUL-terminated drive root lives through this call.
        #[allow(unsafe_code)]
        let kind = unsafe { GetDriveTypeW(root.as_ptr()) };
        if !matches!(kind, 2 | 3 | 5 | 6) {
            return false;
        }
    }
    // Inspect from the root outward so a parent junction/symlink is rejected
    // before querying its child. This also avoids hydrating cloud placeholders.
    for parent in path.ancestors().collect::<Vec<_>>().into_iter().rev() {
        let Ok(meta) = std::fs::symlink_metadata(parent) else {
            return false;
        };
        if meta.file_type().is_symlink() {
            return false;
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if meta.file_attributes() & 0x400 != 0 {
                return false;
            }
        }
    }
    true
}

fn local_regular(path: &Path) -> bool {
    local_path(path) && std::fs::symlink_metadata(path).is_ok_and(|m| m.is_file())
}

pub fn analyze_input(
    analyzer: &mut FileAnalyzer,
    path: &Path,
    ts: i64,
    read_observed: bool,
) -> Option<DownloadedInput> {
    if !local_regular(path) {
        return None;
    }
    let marked = origin::read_marker(path).filter(Origin::is_downloaded);
    if marked.is_none()
        && path_class::classify_here(&path.to_string_lossy()) != PathClass::Downloads
    {
        return None;
    }
    let mut file = if std::fs::metadata(path).ok()?.len() <= MAX_INPUT_SCAN_BYTES {
        analyzer.analyze(path, ts)
    } else {
        // Large media must not stall process/network analysis. Unknown hash means
        // unavailable content inspection; it never permits quarantine or "safe".
        FileAnalyzer::unreadable(&path.to_string_lossy(), ts)
    };
    file.origin = marked.unwrap_or(Origin::Downloaded {
        url: None,
        referrer: None,
    });
    Some(DownloadedInput {
        file,
        observed_at: ts,
        read_observed,
    })
}

pub fn command_inputs(
    analyzer: &mut FileAnalyzer,
    exe: &str,
    cmdline: &str,
    ts: i64,
) -> Vec<DownloadedInput> {
    let mut inputs = Vec::new();
    if cmdline.len() > 32 * 1024 || background_reader(exe) || script::is_interpreter(exe) {
        return inputs;
    }
    // Absolute local operands only: no URL decoding or guessed working directory.
    for operand in script::split_cmdline(cmdline).into_iter().skip(1).take(32) {
        let path = PathBuf::from(operand);
        if path == Path::new(exe)
            || inputs
                .iter()
                .any(|i: &DownloadedInput| Path::new(&i.file.path) == path)
        {
            continue;
        }
        if let Some(input) = analyze_input(analyzer, &path, ts, false) {
            inputs.push(input);
            if inputs.len() == MAX_INPUTS {
                break;
            }
        }
    }
    inputs
}

/// Shell/indexer/AV reads do not make every later desktop launch tainted.
pub fn background_reader(exe: &str) -> bool {
    let name = exe
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(exe)
        .to_ascii_lowercase();
    matches!(
        name.as_str(),
        "explorer.exe"
            | "searchindexer.exe"
            | "searchprotocolhost.exe"
            | "searchfilterhost.exe"
            | "msmpeng.exe"
            | "mssense.exe"
            | "whohack-service.exe"
            | "whohack-service"
            | "finder"
            | "mdworker"
            | "mds"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn local_downloads_are_data_not_scripts_and_large_media_stays_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("movie.mp4");
        std::fs::write(&file, b"harmless fixture").unwrap();
        origin::mark_downloaded(&file, "https://example.invalid/movie").unwrap();
        let mut analyzer = FileAnalyzer::new(None);
        let args = format!(
            "player \"{}\" https://example.invalid/movie",
            file.display()
        );
        let found = command_inputs(&mut analyzer, "player", &args, 100);
        assert_eq!(found.len(), 1);
        assert!(!found[0].read_observed);
        assert_ne!(found[0].file.sha256, [0; 32]);
        assert!(command_inputs(&mut analyzer, "explorer.exe", &args, 100).is_empty());
        std::fs::OpenOptions::new()
            .write(true)
            .open(&file)
            .unwrap()
            .set_len(MAX_INPUT_SCAN_BYTES + 1)
            .unwrap();
        let large = analyze_input(&mut analyzer, &file, 101, true).unwrap();
        assert_eq!(large.file.sha256, [0; 32]);
        assert!(large.file.origin.is_downloaded());
        assert!(analyze_input(&mut analyzer, Path::new("relative.mp4"), 100, false).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn parent_symlink_is_not_followed_for_input_scanning() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("Downloads");
        std::fs::create_dir(&real).unwrap();
        std::fs::write(real.join("clip.mp4"), b"harmless").unwrap();
        let alias = dir.path().join("alias");
        std::os::unix::fs::symlink(real, &alias).unwrap();
        assert!(!local_regular(&alias.join("clip.mp4")));
    }

    #[test]
    fn observed_read_taints_existing_reader_and_children_but_not_a_reused_pid() {
        use crate::{ProcessTracker, TaintEngine};
        use whohack_core::{Event, EventKind, SensitiveClass};
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("sound.wav");
        let exe = dir.path().join("reader");
        std::fs::write(&file, b"harmless sound fixture").unwrap();
        std::fs::write(&exe, b"harmless reader fixture").unwrap();
        origin::mark_downloaded(&file, "https://example.invalid/sound").unwrap();
        let mut engine = TaintEngine::new(FileAnalyzer::new(None), ProcessTracker::default());
        let start = |pid, ppid, ts| Event {
            pid,
            ts,
            kind: EventKind::ProcessStart {
                ppid,
                exe: exe.to_string_lossy().into_owned(),
                cmdline: None,
            },
        };
        let initial = engine.observe(start(51, 1, 100), 100);
        assert!(!initial.process.unwrap().tainted);
        let read = |ts| Event {
            pid: 51,
            ts,
            kind: EventKind::FileAccess {
                path: file.to_string_lossy().into_owned(),
                class: SensitiveClass::Other,
                write: false,
            },
        };
        let observed = engine.observe(read(101), 101).process.unwrap();
        assert!(observed.tainted && observed.downloaded_inputs[0].read_observed);
        assert!(observed.script.is_none());
        assert_eq!(observed.exe.path, exe.to_string_lossy());
        let child = engine.observe(start(52, 51, 102), 102).process.unwrap();
        assert!(child.tainted);
        assert_eq!(child.downloaded_inputs, observed.downloaded_inputs);
        engine.observe(
            Event {
                pid: 51,
                ts: 103,
                kind: EventKind::ProcessExit,
            },
            103,
        );
        engine.observe(start(51, 1, 200), 200);
        assert!(engine.observe(read(150), 201).process.is_none());
        assert!(!engine.process(51).unwrap().tainted);
    }
}
