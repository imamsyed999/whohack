//! Metadata-only, notification-class fanotify on explicitly selected roots.
//! Mount marks cover descendants; every event is filtered back to the roots.
//! FAN_REPORT_PIDFD (Linux 5.15+) prevents guessing a recycled actor PID.
#![allow(unsafe_code)]
use crate::{
    files::{Change, FileSignals},
    health::Health,
};
use anyhow::{Context, Result, ensure};
use async_trait::async_trait;
use std::{
    ffi::CString,
    fs,
    hash::{Hash, Hasher},
    io,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::PathBuf,
    sync::{Arc, atomic::Ordering},
};
use tokio::{io::unix::AsyncFd, sync::mpsc};
use whohack_core::{Event, Os, config::SensitiveConfig, time::now_ms};

#[derive(Debug)]
pub struct Fanotify {
    fd: OwnedFd,
    roots: Vec<PathBuf>,
    sensitive: SensitiveConfig,
    health: Arc<Health>,
    boot_ms: i64,
    ticks: i64,
}

#[derive(Debug)]
struct Record {
    len: usize,
    mask: u64,
    fd: i32,
    pid: i32,
    pidfd: Option<i32>,
}

fn record(b: &[u8]) -> Result<Record> {
    ensure!(b.len() >= 24, "truncated fanotify header");
    let len = u32::from_ne_bytes(b[0..4].try_into()?) as usize;
    let meta_len = u16::from_ne_bytes(b[6..8].try_into()?) as usize;
    ensure!(
        b[4] == libc::FANOTIFY_METADATA_VERSION
            && meta_len >= 24
            && meta_len <= len
            && len <= b.len(),
        "invalid fanotify frame"
    );
    let mut r = Record {
        len,
        mask: u64::from_ne_bytes(b[8..16].try_into()?),
        fd: i32::from_ne_bytes(b[16..20].try_into()?),
        pid: i32::from_ne_bytes(b[20..24].try_into()?),
        pidfd: None,
    };
    let mut offset = meta_len;
    while offset < len {
        ensure!(offset + 4 <= len, "truncated fanotify info header");
        let info_len = u16::from_ne_bytes(b[offset + 2..offset + 4].try_into()?) as usize;
        ensure!(
            info_len >= 4 && offset + info_len <= len,
            "invalid fanotify info length"
        );
        if b[offset] == libc::FAN_EVENT_INFO_TYPE_PIDFD {
            ensure!(info_len >= 8 && r.pidfd.is_none(), "invalid fanotify pidfd");
            r.pidfd = Some(i32::from_ne_bytes(b[offset + 4..offset + 8].try_into()?));
        }
        offset += info_len;
    }
    Ok(r)
}

impl Fanotify {
    pub fn new(
        roots: &[PathBuf],
        sensitive: &SensitiveConfig,
        health: Arc<Health>,
    ) -> Result<Self> {
        ensure!(
            !roots.is_empty() && roots.len() <= 64,
            "fanotify needs 1..64 directory roots"
        );
        let roots: Vec<_> = roots
            .iter()
            .map(fs::canonicalize)
            .collect::<io::Result<_>>()?;
        ensure!(
            roots.iter().all(|p| p.is_dir()),
            "fanotify roots must be directories"
        );
        // Notification class cannot block or allow another process's file access.
        let fd = unsafe {
            libc::fanotify_init(
                libc::FAN_CLASS_NOTIF
                    | libc::FAN_CLOEXEC
                    | libc::FAN_NONBLOCK
                    | libc::FAN_REPORT_PIDFD,
                (libc::O_RDONLY | libc::O_LARGEFILE | libc::O_CLOEXEC) as u32,
            )
        };
        ensure!(
            fd >= 0,
            "fanotify (requires CAP_SYS_ADMIN and Linux 5.15+): {}",
            io::Error::last_os_error()
        );
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let mask = libc::FAN_ACCESS | libc::FAN_MODIFY | libc::FAN_EVENT_ON_CHILD;
        for path in &roots {
            let path = CString::new(path.as_os_str().as_bytes())?;
            let rc = unsafe {
                libc::fanotify_mark(
                    fd.as_raw_fd(),
                    libc::FAN_MARK_ADD | libc::FAN_MARK_MOUNT,
                    mask,
                    libc::AT_FDCWD,
                    path.as_ptr(),
                )
            };
            ensure!(rc == 0, "fanotify mark: {}", io::Error::last_os_error());
        }
        let boot_ms = super::procfs::parse_btime_ms(&fs::read_to_string("/proc/stat")?)
            .context("missing boot time")?;
        Ok(Self {
            fd,
            roots,
            sensitive: sensitive.clone(),
            health,
            boot_ms,
            ticks: super::clock_ticks_per_sec(),
        })
    }

    fn actor(&self, pid: i32, pidfd: &OwnedFd) -> Option<i64> {
        if pid <= 0 {
            return None;
        }
        let identity = || -> Option<i32> {
            fs::read_to_string(format!("/proc/self/fdinfo/{}", pidfd.as_raw_fd()))
                .ok()?
                .lines()
                .find_map(|s| s.strip_prefix("Pid:").and_then(|v| v.trim().parse().ok()))
        };
        if identity()? != pid {
            return None;
        }
        let stat =
            super::procfs::parse_stat(&fs::read_to_string(format!("/proc/{pid}/stat")).ok()?)?;
        if identity()? != pid {
            return None;
        }
        Some(self.boot_ms + ((stat.start_ticks as u128 * 1000) / self.ticks as u128) as i64)
    }

    fn events(&self, b: &[u8], signals: &mut FileSignals) -> Result<Vec<Event>> {
        let mut out = Vec::new();
        let mut offset = 0;
        while offset < b.len() {
            let r = record(&b[offset..])?;
            offset += r.len;
            // Every descriptor returned by the kernel is closed, including events
            // outside configured roots and ones whose actor has already exited.
            let file = (r.fd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(r.fd) });
            let actor = r
                .pidfd
                .filter(|fd| *fd >= 0)
                .map(|fd| unsafe { OwnedFd::from_raw_fd(fd) });
            if r.mask & libc::FAN_Q_OVERFLOW != 0 {
                self.health.kernel_lost.fetch_add(1, Ordering::Relaxed);
                *signals = FileSignals::new(Os::Linux, &self.sensitive);
                continue;
            }
            let Some(file) = file else {
                continue;
            };
            let path = match fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd())) {
                Ok(p) => p,
                Err(_) => continue,
            };
            if !self.roots.iter().any(|root| path.starts_with(root)) {
                continue;
            }
            let Some(born) = actor.as_ref().and_then(|a| self.actor(r.pid, a)) else {
                self.health.unattributed();
                continue;
            };
            let metadata = fs::File::from(file).metadata()?;
            if !metadata.is_file() {
                continue;
            }
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            (metadata.dev(), metadata.ino()).hash(&mut hasher);
            let id = hasher.finish();
            let ts = now_ms();
            let path = path.to_string_lossy();
            if r.mask & libc::FAN_ACCESS != 0 {
                out.extend(signals.access(r.pid as u32, born, ts, id, &path, Change::Read));
            }
            if r.mask & libc::FAN_MODIFY != 0 {
                out.extend(signals.access(r.pid as u32, born, ts, id, &path, Change::Write));
            }
        }
        Ok(out)
    }
}

#[async_trait]
impl crate::Collector for Fanotify {
    fn name(&self) -> &'static str {
        "linux-fanotify"
    }
    async fn run(&self, tx: mpsc::Sender<Event>) -> Result<()> {
        let fd = AsyncFd::new(self.fd.try_clone()?)?;
        let mut signals = FileSignals::new(Os::Linux, &self.sensitive);
        let mut buf = vec![0u8; 64 * 1024];
        self.health.files.store(true, Ordering::Relaxed);
        loop {
            let mut ready = tokio::select! { _ = tx.closed() => break, r = fd.readable() => r? };
            let n = match ready.try_io(|inner| {
                let n = unsafe {
                    libc::read(
                        inner.get_ref().as_raw_fd(),
                        buf.as_mut_ptr().cast(),
                        buf.len(),
                    )
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(r) => r?,
                Err(_) => continue,
            };
            ensure!(n > 0, "fanotify closed unexpectedly");
            for event in self.events(&buf[..n], &mut signals)? {
                if let Err(mpsc::error::TrySendError::Full(_)) = tx.try_send(event) {
                    self.health.dropped.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        self.health.files.store(false, Ordering::Relaxed);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_frames_require_valid_version_lengths_and_pidfd() {
        let mut b = vec![0u8; 32];
        b[0..4].copy_from_slice(&32u32.to_ne_bytes());
        b[4] = libc::FANOTIFY_METADATA_VERSION;
        b[6..8].copy_from_slice(&24u16.to_ne_bytes());
        b[16..20].copy_from_slice(&(-1i32).to_ne_bytes());
        b[24] = libc::FAN_EVENT_INFO_TYPE_PIDFD;
        b[26..28].copy_from_slice(&8u16.to_ne_bytes());
        b[28..32].copy_from_slice(&42i32.to_ne_bytes());
        let r = record(&b).unwrap();
        assert_eq!(r.pidfd, Some(42));
        assert_eq!(r.len, 32);
        assert!(record(&b[..31]).is_err());
        b[26..28].copy_from_slice(&3u16.to_ne_bytes());
        assert!(record(&b).is_err());
        b[4] = 255;
        assert!(record(&b).is_err());
    }
}
