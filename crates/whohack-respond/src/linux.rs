//! pidfds prevent signals from reaching a reused PID. nftables rules are
//! scoped to a private cgroup and table, never the host's existing ruleset.
use crate::{Backend, Capabilities, Lease};
use anyhow::{Context, Result, bail, ensure};
use std::fs;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use whohack_core::ProcessInfo;

#[derive(Debug)]
pub struct LinuxBackend;
fn nft_path() -> Option<&'static str> {
    ["/usr/sbin/nft", "/usr/bin/nft"]
        .into_iter()
        .find(|p| Path::new(p).is_file())
}
impl Backend for LinuxBackend {
    fn capabilities(&self) -> Capabilities {
        // SAFETY: geteuid has no arguments or memory side effects.
        let privileged = unsafe { libc::geteuid() } == 0;
        Capabilities { network: privileged && nft_path().is_some() && Path::new("/sys/fs/cgroup/cgroup.controllers").exists(),
            suspend: true, terminate: true, quarantine: true,
            network_scope: "New sockets opened by the target process and its children in a private cgroup".into(),
            limitation: "Network response requires root, cgroup v2 and nftables. Existing sockets retain their previous cgroup. Suspension requires manual recovery after a service crash.".into() }
    }
    fn block(&mut self, target: &ProcessInfo) -> Result<Box<dyn Lease>> {
        Ok(Box::new(NetworkBlock::new(target)?))
    }
    fn suspend(&mut self, target: &ProcessInfo) -> Result<Box<dyn Lease>> {
        Ok(Box::new(Suspension::new(target)?))
    }
    fn terminate(&mut self, target: &ProcessInfo) -> Result<()> {
        let p = open(target)?;
        signal(&p, libc::SIGKILL)
    }
    fn recover_release(
        &mut self,
        target: &ProcessInfo,
        action: whohack_core::Action,
        data: &serde_json::Value,
    ) -> Result<()> {
        if action == whohack_core::Action::SuspendAndAsk {
            ensure!(
                data.get("stopped") == Some(&serde_json::Value::Bool(true)),
                "no completed suspension record"
            );
            return signal(&open(target)?, libc::SIGCONT);
        }
        ensure!(
            action == whohack_core::Action::BlockNetwork,
            "operation has no reversible process state"
        );
        let table = data
            .get("table")
            .and_then(|v| v.as_str())
            .context("missing response table identity")?;
        ensure!(
            valid_response_table(table),
            "invalid response table identity"
        );
        let original = data
            .get("original")
            .and_then(|v| v.as_str())
            .context("missing original cgroup")?;
        ensure!(
            original.starts_with("/sys/fs/cgroup/") && !original.split('/').any(|p| p == ".."),
            "invalid original cgroup"
        );
        let mut block = NetworkBlock {
            target: target.clone(),
            original: PathBuf::from(original),
            group: Path::new("/sys/fs/cgroup").join(table),
            table: table.into(),
            installed: true,
        };
        block.release()
    }
}

fn valid_response_table(table: &str) -> bool {
    // Journals written before the product rename must remain recoverable.
    table
        .strip_prefix("whohack_")
        .or_else(|| table.strip_prefix("vigil_"))
        .is_some_and(|suffix| suffix.len() == 32 && suffix.bytes().all(|b| b.is_ascii_hexdigit()))
}

#[test]
fn response_table_identity_accepts_both_product_generations() {
    for prefix in ["whohack_", "vigil_"] {
        assert!(valid_response_table(&format!("{prefix}{:032x}", 42)));
        assert!(!valid_response_table(&format!("{prefix}42")));
        assert!(!valid_response_table(&format!(
            "{prefix}{};",
            "a".repeat(31)
        )));
    }
    assert!(!valid_response_table(&format!(
        "unrelated_{}",
        "a".repeat(32)
    )));
}

fn open(target: &ProcessInfo) -> Result<OwnedFd> {
    crate::guard(target)?;
    // SAFETY: syscall with scalar pid/flags. On success we own the returned fd.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, target.pid, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
    validate(target)?;
    signal(&fd, 0)?;
    Ok(fd)
}
fn validate(target: &ProcessInfo) -> Result<()> {
    let stat = fs::read_to_string(format!("/proc/{}/stat", target.pid))?;
    let fields: Vec<_> = stat
        .rsplit_once(')')
        .context("invalid proc stat")?
        .1
        .split_whitespace()
        .collect();
    let ticks: i64 = fields.get(19).context("missing creation ticks")?.parse()?;
    let boot: i64 = fs::read_to_string("/proc/stat")?
        .lines()
        .find_map(|l| l.strip_prefix("btime ").map(str::to_owned))
        .context("missing boot time")?
        .parse()?;
    // SAFETY: sysconf has no pointer arguments.
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    ensure!(hz > 0, "clock frequency unavailable");
    ensure!(
        boot * 1000 + ticks * 1000 / hz == target.start_time,
        "stale alert: process creation time changed"
    );
    let exe = PathBuf::from(format!("/proc/{}/exe", target.pid));
    ensure!(
        fs::read_link(&exe)? == Path::new(&target.exe.path),
        "stale alert: process image changed"
    );
    ensure!(
        crate::digest_file(&exe)? == target.exe.sha256,
        "stale alert: image digest changed"
    );
    Ok(())
}
fn signal(fd: &OwnedFd, sig: i32) -> Result<()> {
    // SAFETY: valid owned fd, null siginfo selects the kernel's standard signal.
    if unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd.as_raw_fd(),
            sig,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    } < 0
    {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}
#[derive(Debug)]
struct Suspension {
    fd: OwnedFd,
    active: bool,
}
impl Suspension {
    fn new(target: &ProcessInfo) -> Result<Self> {
        let fd = open(target)?;
        let stat = fs::read_to_string(format!("/proc/{}/stat", target.pid))?;
        let state = stat
            .rsplit_once(')')
            .context("invalid proc stat")?
            .1
            .trim_start()
            .chars()
            .next();
        ensure!(
            !matches!(state, Some('T' | 't')),
            "process was already stopped by another owner"
        );
        signal(&fd, libc::SIGSTOP)?;
        Ok(Self { fd, active: true })
    }
}
impl Lease for Suspension {
    fn recovery_data(&self) -> serde_json::Value {
        serde_json::json!({"stopped": self.active})
    }
    fn release(&mut self) -> Result<()> {
        if self.active {
            if let Err(e) = signal(&self.fd, libc::SIGCONT)
                && e.downcast_ref::<io::Error>()
                    .and_then(io::Error::raw_os_error)
                    != Some(libc::ESRCH)
            {
                return Err(e);
            }
            self.active = false;
        }
        Ok(())
    }
}
impl Drop for Suspension {
    fn drop(&mut self) {
        let _ = self.release();
    }
}

fn nft(script: &str) -> Result<()> {
    let mut child =
        Command::new(nft_path().context("install nftables to enable network response")?)
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;
    child
        .stdin
        .take()
        .context("nft stdin")?
        .write_all(script.as_bytes())?;
    let result = child.wait_with_output()?;
    ensure!(
        result.status.success(),
        "nftables rejected response: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(())
}
#[derive(Debug)]
struct NetworkBlock {
    target: ProcessInfo,
    original: PathBuf,
    group: PathBuf,
    table: String,
    installed: bool,
}
impl NetworkBlock {
    fn new(target: &ProcessInfo) -> Result<Self> {
        let _process = open(target)?;
        let original = fs::read_to_string(format!("/proc/{}/cgroup", target.pid))?
            .lines()
            .find_map(|l| l.strip_prefix("0::").map(str::to_owned))
            .context("cgroup v2 is required")?;
        ensure!(
            original.starts_with('/') && !original.split('/').any(|p| p == ".."),
            "unsafe cgroup path"
        );
        let table = format!("whohack_{:032x}", rand::random::<u128>());
        let group = Path::new("/sys/fs/cgroup").join(&table);
        fs::create_dir(&group).context("create private response cgroup (root required)")?;
        let mut result = Self {
            target: target.clone(),
            original: Path::new("/sys/fs/cgroup").join(original.trim_start_matches('/')),
            group,
            table,
            installed: false,
        };
        // Atomic nft transaction, accepting everything outside our private group.
        nft(&format!(
            "add table inet {t}\nadd chain inet {t} output {{ type filter hook output priority -10; policy accept; }}\nadd rule inet {t} output socket cgroupv2 level 1 \"{t}\" counter drop\n",
            t = result.table
        )).context("install cgroup socket filter; the kernel must enable CONFIG_NFT_SOCKET")?;
        result.installed = true;
        validate(target)?;
        fs::write(result.group.join("cgroup.procs"), target.pid.to_string())?;
        validate(target)?;
        Ok(result)
    }
}
impl Lease for NetworkBlock {
    fn intact(&self) -> Result<bool> {
        if !self.installed {
            return Ok(false);
        }
        let output = Command::new(nft_path().context("nftables is unavailable")?)
            .args(["--json", "list", "table", "inet", &self.table])
            .output()?;
        ensure!(
            output.status.success(),
            "private response table is unavailable"
        );
        ensure!(
            output.stdout.len() <= 1024 * 1024,
            "response table exceeds inspection limit"
        );
        let document: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        let entries = document["nftables"]
            .as_array()
            .context("invalid nftables response")?;
        let chain = entries.iter().any(|entry| {
            let c = &entry["chain"];
            c["family"] == "inet"
                && c["table"] == self.table
                && c["name"] == "output"
                && c["type"] == "filter"
                && c["hook"] == "output"
                && c["prio"] == -10
        });
        let rule = entries.iter().any(|entry| {
            let r = &entry["rule"];
            r["family"] == "inet"
                && r["table"] == self.table
                && r["chain"] == "output"
                && r["expr"].as_array().is_some_and(|expr| {
                    let matches = expr.iter().any(|e| {
                        let m = &e["match"];
                        m["op"] == "=="
                            && m["left"]["socket"]["key"] == "cgroupv2"
                            && m["left"]["socket"]["level"] == 1
                            && m["right"] == self.table
                    });
                    matches
                        && expr
                            .iter()
                            .any(|e| e.as_object().is_some_and(|o| o.contains_key("drop")))
                })
        });
        Ok(chain && rule)
    }
    fn recovery_data(&self) -> serde_json::Value {
        serde_json::json!({"table": self.table, "original": self.original})
    }
    fn release(&mut self) -> Result<()> {
        if self.installed {
            // One atomic batch works on older nftables too: `add` is idempotent,
            // so deletion also succeeds if another owner already removed it.
            // Never flush or enumerate the host's unrelated tables for recovery.
            nft(&format!(
                "add table inet {t}\ndelete table inet {t}\n",
                t = self.table
            ))?;
            self.installed = false;
        }
        // Move only the original, still-identical target; children keep their
        // cgroup until they exit, but the table is gone and traffic is allowed.
        if validate(&self.target).is_ok() {
            let current = fs::read_to_string(format!("/proc/{}/cgroup", self.target.pid))?;
            if current.lines().any(|l| l == format!("0::/{}", self.table)) {
                fs::write(
                    self.original.join("cgroup.procs"),
                    self.target.pid.to_string(),
                )?;
            }
        }
        if let Err(e) = fs::remove_dir(&self.group)
            && !matches!(
                e.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::DirectoryNotEmpty
            )
        {
            bail!(e);
        }
        Ok(())
    }
}
impl Drop for NetworkBlock {
    fn drop(&mut self) {
        let _ = self.release();
    }
}

#[cfg(test)]
#[path = "linux/acceptance.rs"]
mod acceptance;

#[cfg(test)]
mod tests {
    use super::*;
    use whohack_core::{FileInfo, Origin, PathClass, SignState};
    #[test]
    fn rejects_stale_identity_before_signalling_owned_child() {
        let mut child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        let p = ProcessInfo {
            downloaded_inputs: Vec::new(),
            pid: child.id(),
            ppid: std::process::id(),
            start_time: 1,
            exe: FileInfo {
                path: "/bin/sleep".into(),
                sha256: [1; 32],
                origin: Origin::Unknown,
                sign: SignState::Unsigned,
                yara_hits: vec![],
                first_seen: 1,
            },
            script: None,
            path_class: PathClass::Other,
            tainted: false,
            taint_root: None,
            app_id: "owned-test".into(),
        };
        assert!(
            LinuxBackend
                .terminate(&p)
                .unwrap_err()
                .to_string()
                .contains("creation time")
        );
        assert!(child.try_wait().unwrap().is_none());
        child.kill().unwrap();
        child.wait().unwrap();
    }
}
