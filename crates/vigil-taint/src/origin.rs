//! Download origin markers (SPEC §8).
//!
//! | OS | Marker |
//! |---|---|
//! | Windows | `Zone.Identifier` alternate data stream (Mark-of-the-Web) |
//! | macOS | `com.apple.quarantine` extended attribute |
//! | Linux | `user.xdg.origin.url` / `user.xdg.referrer.url` extended attributes |
//!
//! Parsers are pure; readers touch the filesystem.

use std::path::Path;

use vigil_core::Origin;

/// Parses a Mark-of-the-Web stream. Zones 3 (Internet) and 4 (Restricted)
/// mean downloaded; local, intranet, and trusted zones do not.
pub fn parse_zone_identifier(text: &str) -> Option<Origin> {
    let mut zone = None;
    let mut host = None;
    let mut referrer = None;
    for line in text.lines() {
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let v = v.trim();
        match k.trim().to_ascii_lowercase().as_str() {
            "zoneid" => zone = v.parse::<u32>().ok(),
            "hosturl" => host = Some(v.to_string()),
            "referrerurl" => referrer = Some(v.to_string()),
            _ => {}
        }
    }
    let useful = |u: Option<String>| u.filter(|s| !s.is_empty() && s != "about:internet");
    match zone? {
        3 | 4 => Some(Origin::Downloaded {
            url: useful(host),
            referrer: useful(referrer),
        }),
        _ => None,
    }
}

/// Parses a `com.apple.quarantine` value (`flags;hextime;agent;uuid`). Any
/// well-formed value marks the file as downloaded. The source URL lives in
/// the per-user LaunchServices database and is not read here.
pub fn parse_quarantine(value: &str) -> Option<Origin> {
    let flags = value.split(';').next()?;
    u32::from_str_radix(flags, 16).ok()?;
    Some(Origin::Downloaded {
        url: None,
        referrer: None,
    })
}

/// Builds an origin from the XDG attributes browsers set on Linux.
pub fn from_xdg(origin_url: Option<String>, referrer_url: Option<String>) -> Option<Origin> {
    let origin_url = origin_url.filter(|s| !s.is_empty())?;
    Some(Origin::Downloaded {
        url: Some(origin_url),
        referrer: referrer_url.filter(|s| !s.is_empty()),
    })
}

/// Reads the OS download marker for `path`, if any.
pub fn read_marker(path: &Path) -> Option<Origin> {
    #[cfg(windows)]
    {
        let mut ads = path.as_os_str().to_owned();
        ads.push(":Zone.Identifier");
        let text = std::fs::read_to_string(&ads).ok()?;
        parse_zone_identifier(&text)
    }
    #[cfg(target_os = "macos")]
    {
        let raw = xattr::get(path, "com.apple.quarantine")?;
        parse_quarantine(&String::from_utf8_lossy(&raw))
    }
    #[cfg(target_os = "linux")]
    {
        let text = |name| xattr::get(path, name).map(|b| String::from_utf8_lossy(&b).into_owned());
        from_xdg(text("user.xdg.origin.url"), text("user.xdg.referrer.url"))
    }
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        let _ = path;
        None
    }
}

#[cfg(unix)]
pub(crate) mod xattr {
    //! Minimal extended-attribute access.
    #![allow(unsafe_code)]

    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    const MAX: usize = 4096;

    pub fn get(path: &Path, name: &str) -> Option<Vec<u8>> {
        let p = CString::new(path.as_os_str().as_bytes()).ok()?;
        let n = CString::new(name).ok()?;
        let mut buf = vec![0u8; MAX];
        // SAFETY: p and n are NUL-terminated; buf has MAX bytes.
        #[cfg(target_os = "linux")]
        let len =
            unsafe { libc::getxattr(p.as_ptr(), n.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
        // SAFETY: as above; position 0 and options 0 read the whole attribute.
        #[cfg(target_os = "macos")]
        let len = unsafe {
            libc::getxattr(
                p.as_ptr(),
                n.as_ptr(),
                buf.as_mut_ptr().cast(),
                buf.len(),
                0,
                0,
            )
        };
        if len < 0 {
            return None;
        }
        buf.truncate(len as usize);
        Some(buf)
    }

    /// Sets an attribute (tests and tooling).
    pub fn set(path: &Path, name: &str, value: &[u8]) -> std::io::Result<()> {
        let p = CString::new(path.as_os_str().as_bytes())?;
        let n = CString::new(name)?;
        // SAFETY: p and n are NUL-terminated; value is a valid slice.
        #[cfg(target_os = "linux")]
        let rc = unsafe {
            libc::setxattr(
                p.as_ptr(),
                n.as_ptr(),
                value.as_ptr().cast(),
                value.len(),
                0,
            )
        };
        // SAFETY: as above.
        #[cfg(target_os = "macos")]
        let rc = unsafe {
            libc::setxattr(
                p.as_ptr(),
                n.as_ptr(),
                value.as_ptr().cast(),
                value.len(),
                0,
                0,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

/// Marks `path` as downloaded from `url` using the current OS's marker.
/// Used by tests and by `tools/beacon-sim` to simulate a browser download.
pub fn mark_downloaded(path: &Path, url: &str) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        let mut ads = path.as_os_str().to_owned();
        ads.push(":Zone.Identifier");
        std::fs::write(
            &ads,
            format!("[ZoneTransfer]\r\nZoneId=3\r\nHostUrl={url}\r\n"),
        )
    }
    #[cfg(target_os = "linux")]
    {
        xattr::set(path, "user.xdg.origin.url", url.as_bytes())
    }
    #[cfg(target_os = "macos")]
    {
        let _ = url;
        xattr::set(path, "com.apple.quarantine", b"0081;00000000;Vigil;")
    }
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        let _ = (path, url);
        Err(std::io::Error::other("unsupported OS"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zone_identifier() {
        let motw = "[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://example.com/page\r\nHostUrl=https://example.com/a.exe\r\n";
        assert_eq!(
            parse_zone_identifier(motw),
            Some(Origin::Downloaded {
                url: Some("https://example.com/a.exe".into()),
                referrer: Some("https://example.com/page".into()),
            })
        );
        assert_eq!(
            parse_zone_identifier("[ZoneTransfer]\nZoneId=4\nHostUrl=about:internet\n"),
            Some(Origin::Downloaded {
                url: None,
                referrer: None
            })
        );
        for local in [
            "[ZoneTransfer]\nZoneId=0",
            "[ZoneTransfer]\nZoneId=1",
            "[ZoneTransfer]\nZoneId=2",
        ] {
            assert_eq!(parse_zone_identifier(local), None);
        }
        assert_eq!(parse_zone_identifier("garbage"), None);
    }

    #[test]
    fn quarantine() {
        assert!(parse_quarantine("0083;5f1b2c3d;Safari;8E1F-UUID").is_some());
        assert!(parse_quarantine("0081;00000000;Vigil;").is_some());
        assert!(parse_quarantine("zz;1;2").is_none());
    }

    #[test]
    fn xdg() {
        assert_eq!(
            from_xdg(Some("https://example.com/x".into()), Some(String::new())),
            Some(Origin::Downloaded {
                url: Some("https://example.com/x".into()),
                referrer: None
            })
        );
        assert_eq!(from_xdg(None, Some("r".into())), None);
        assert_eq!(from_xdg(Some(String::new()), None), None);
    }

    #[test]
    fn mark_and_read_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("dl.bin");
        std::fs::write(&f, b"x").unwrap();
        assert_eq!(read_marker(&f), None);
        match mark_downloaded(&f, "https://example.com/dl.bin") {
            Ok(()) => assert!(matches!(read_marker(&f), Some(Origin::Downloaded { .. }))),
            // Some filesystems (e.g. tmpfs without user xattrs) refuse; nothing to assert.
            Err(e) => eprintln!("skipping: marker not supported here: {e}"),
        }
    }
}
