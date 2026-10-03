//! Coarse classification of executable locations (SPEC §7 `PathClass`).

use vigil_core::{Os, PathClass};

/// Classifies `path` using the rules for `os`. Pure; no filesystem access.
pub fn classify(path: &str, os: Os) -> PathClass {
    match os {
        Os::Windows => windows(path),
        Os::MacOs => macos(path),
        Os::Linux => linux(path),
    }
}

/// Classifies for the OS this binary runs on.
pub fn classify_here(path: &str) -> PathClass {
    classify(path, Os::current())
}

fn windows(path: &str) -> PathClass {
    let p = path.replace('/', "\\").to_ascii_lowercase();
    // Strip a drive prefix ("c:") so rules apply to any drive.
    let rest = match p.as_bytes() {
        [d, b':', b'\\', ..] if d.is_ascii_alphabetic() => &p[2..],
        _ => p.as_str(),
    };
    let in_users = rest.starts_with("\\users\\");
    if in_users && rest.contains("\\downloads\\") {
        PathClass::Downloads
    } else if rest.contains("\\appdata\\local\\temp\\")
        || rest.starts_with("\\windows\\temp\\")
        || rest.starts_with("\\temp\\")
    {
        PathClass::Temp
    } else if rest.starts_with("\\windows\\") {
        PathClass::System
    } else if rest.starts_with("\\program files\\") || rest.starts_with("\\program files (x86)\\") {
        PathClass::ProgramFiles
    } else if in_users && rest.contains("\\appdata\\") {
        PathClass::UserApp
    } else {
        PathClass::Other
    }
}

/// `/<prefix>/<name>/...` → the part after the user name, if `path` is under `prefix`.
fn under_home<'a>(path: &'a str, prefix: &str) -> Option<&'a str> {
    let rest = path.strip_prefix(prefix)?;
    let (_user, after) = rest.split_once('/')?;
    Some(after)
}

fn macos(path: &str) -> PathClass {
    let lower = path.to_ascii_lowercase();
    if let Some(after) = under_home(&lower, "/users/") {
        return if after.starts_with("downloads/") {
            PathClass::Downloads
        } else {
            PathClass::UserApp
        };
    }
    const TEMP: &[&str] = &[
        "/tmp/",
        "/private/tmp/",
        "/var/folders/",
        "/private/var/folders/",
        "/var/tmp/",
    ];
    const SYSTEM: &[&str] = &[
        "/system/",
        "/usr/bin/",
        "/usr/sbin/",
        "/bin/",
        "/sbin/",
        "/usr/libexec/",
        "/usr/lib/",
    ];
    const PROGRAMS: &[&str] = &[
        "/applications/",
        "/library/",
        "/opt/homebrew/",
        "/usr/local/",
        "/opt/",
    ];
    if TEMP.iter().any(|t| lower.starts_with(t)) {
        PathClass::Temp
    } else if SYSTEM.iter().any(|t| lower.starts_with(t)) {
        PathClass::System
    } else if PROGRAMS.iter().any(|t| lower.starts_with(t)) {
        PathClass::ProgramFiles
    } else {
        PathClass::Other
    }
}

fn linux(path: &str) -> PathClass {
    let home_rest = under_home(path, "/home/").or_else(|| path.strip_prefix("/root/"));
    if let Some(after) = home_rest {
        return if after.starts_with("Downloads/") || after.starts_with("downloads/") {
            PathClass::Downloads
        } else {
            PathClass::UserApp
        };
    }
    const TEMP: &[&str] = &["/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/"];
    const SYSTEM: &[&str] = &[
        "/usr/bin/",
        "/usr/sbin/",
        "/bin/",
        "/sbin/",
        "/usr/lib/",
        "/usr/lib64/",
        "/usr/libexec/",
        "/lib/",
        "/lib64/",
    ];
    const PROGRAMS: &[&str] = &["/opt/", "/usr/local/", "/snap/", "/var/lib/flatpak/"];
    if TEMP.iter().any(|t| path.starts_with(t)) {
        PathClass::Temp
    } else if SYSTEM.iter().any(|t| path.starts_with(t)) {
        PathClass::System
    } else if PROGRAMS.iter().any(|t| path.starts_with(t)) {
        PathClass::ProgramFiles
    } else {
        PathClass::Other
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use PathClass::*;

    #[test]
    fn windows_paths() {
        let w = |p| classify(p, Os::Windows);
        assert_eq!(w(r"C:\Users\Ann\Downloads\setup.exe"), Downloads);
        assert_eq!(w(r"D:\Users\Ann\Downloads\sub\x.exe"), Downloads);
        assert_eq!(w(r"C:\Users\Ann\AppData\Local\Temp\x.exe"), Temp);
        assert_eq!(w(r"C:\Windows\Temp\x.exe"), Temp);
        assert_eq!(w(r"C:\Windows\System32\cmd.exe"), System);
        assert_eq!(w(r"c:\program files\App\app.exe"), ProgramFiles);
        assert_eq!(w(r"C:\Program Files (x86)\App\app.exe"), ProgramFiles);
        assert_eq!(
            w(r"C:\Users\Ann\AppData\Local\Programs\App\app.exe"),
            UserApp
        );
        assert_eq!(w(r"C:\Users\Ann\AppData\Roaming\App\app.exe"), UserApp);
        assert_eq!(w(r"C:\Tools\x.exe"), Other);
        assert_eq!(w("C:/Users/Ann/Downloads/x.exe"), Downloads);
    }

    #[test]
    fn macos_paths() {
        let m = |p| classify(p, Os::MacOs);
        assert_eq!(
            m("/Users/ann/Downloads/App.app/Contents/MacOS/App"),
            Downloads
        );
        assert_eq!(
            m("/Users/ann/Library/Application Support/x/helper"),
            UserApp
        );
        assert_eq!(m("/private/var/folders/ab/T/x"), Temp);
        assert_eq!(m("/tmp/x"), Temp);
        assert_eq!(m("/usr/bin/curl"), System);
        assert_eq!(
            m("/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder"),
            System
        );
        assert_eq!(
            m("/Applications/Safari.app/Contents/MacOS/Safari"),
            ProgramFiles
        );
        assert_eq!(m("/opt/homebrew/bin/wget"), ProgramFiles);
        assert_eq!(m("/Volumes/USB/x"), Other);
    }

    #[test]
    fn linux_paths() {
        let l = |p| classify(p, Os::Linux);
        assert_eq!(l("/home/ann/Downloads/tool"), Downloads);
        assert_eq!(l("/root/Downloads/tool"), Downloads);
        assert_eq!(l("/home/ann/.local/bin/tool"), UserApp);
        assert_eq!(l("/tmp/x"), Temp);
        assert_eq!(l("/dev/shm/x"), Temp);
        assert_eq!(l("/usr/bin/curl"), System);
        assert_eq!(l("/lib64/ld-linux-x86-64.so.2"), System);
        assert_eq!(l("/opt/google/chrome/chrome"), ProgramFiles);
        assert_eq!(l("/snap/firefox/123/firefox"), ProgramFiles);
        assert_eq!(l("/srv/app/run"), Other);
        assert_eq!(
            l("/home/ann"),
            Other,
            "home dir itself is not a file inside it"
        );
    }
}
