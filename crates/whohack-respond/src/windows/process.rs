use crate::Lease;
use anyhow::{Context, Result, bail, ensure};
use std::collections::HashSet;
use std::io;
use whohack_core::ProcessInfo;
use windows_sys::Win32::Foundation::{
    CloseHandle, FILETIME, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
use windows_sys::Win32::System::Threading::*;

#[derive(Debug)]
pub(super) struct Handle(pub HANDLE);
// SAFETY: owned process/thread handles can be used on another thread. The
// manager serializes access; no handle is closed while an API is using it.
unsafe impl Send for Handle {}
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}
fn last() -> anyhow::Error {
    io::Error::last_os_error().into()
}

pub(super) fn open(target: &ProcessInfo, access: u32) -> Result<Handle> {
    crate::guard(target)?;
    // SAFETY: scalar arguments, ownership transferred on success.
    let h = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE | access,
            0,
            target.pid,
        )
    };
    ensure!(
        !h.is_null(),
        "open target process: {}",
        io::Error::last_os_error()
    );
    let h = Handle(h);
    let mut times = [FILETIME::default(); 4];
    let [a, b, c, d] = &mut times;
    if unsafe { GetProcessTimes(h.0, a, b, c, d) } == 0 {
        return Err(last());
    }
    let ticks = (u64::from(times[0].dwHighDateTime) << 32) | u64::from(times[0].dwLowDateTime);
    ensure!(
        (ticks / 10_000) as i64 - 11_644_473_600_000 == target.start_time,
        "stale alert: process creation time changed"
    );
    ensure!(
        unsafe { WaitForSingleObject(h.0, 0) } != WAIT_OBJECT_0,
        "target has exited"
    );
    let mut buf = vec![0u16; 32_768];
    let mut len = buf.len() as u32;
    if unsafe { QueryFullProcessImageNameW(h.0, 0, buf.as_mut_ptr(), &mut len) } == 0 {
        return Err(last());
    }
    let path = String::from_utf16(&buf[..len as usize])?;
    ensure!(
        path.eq_ignore_ascii_case(&target.exe.path),
        "stale alert: process image changed"
    );
    ensure!(
        crate::digest_file(std::path::Path::new(&path))? == target.exe.sha256,
        "stale alert: image digest changed"
    );
    Ok(h)
}

pub(super) fn terminate(target: &ProcessInfo) -> Result<()> {
    let h = open(target, PROCESS_TERMINATE)?;
    if unsafe { TerminateProcess(h.0, 1) } == 0 {
        return Err(last());
    }
    ensure!(
        unsafe { WaitForSingleObject(h.0, 5000) } == WAIT_OBJECT_0,
        "termination did not complete within five seconds"
    );
    Ok(())
}

#[derive(Debug)]
pub(super) struct Suspension {
    threads: Vec<SuspendedThread>,
    _process: Handle,
}
#[derive(Debug)]
struct SuspendedThread {
    handle: Handle,
    state: ThreadState,
}
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct ThreadState {
    id: u32,
    created: u64,
    previous: u32,
}

fn thread_created(h: &Handle) -> Result<u64> {
    let mut times = [FILETIME::default(); 4];
    let [a, b, c, d] = &mut times;
    if unsafe { GetThreadTimes(h.0, a, b, c, d) } == 0 {
        return Err(last());
    }
    Ok((u64::from(times[0].dwHighDateTime) << 32) | u64::from(times[0].dwLowDateTime))
}
impl Suspension {
    pub fn new(target: &ProcessInfo) -> Result<Self> {
        let h = open(target, 0)?;
        let mut result = Self {
            threads: vec![],
            _process: h,
        };
        let mut seen = HashSet::new();
        // Repeat snapshots until no new threads remain. Failing or racing
        // snapshots roll back all of our increments through Drop.
        for _ in 0..8 {
            let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
            ensure!(
                snap != INVALID_HANDLE_VALUE,
                "thread snapshot: {}",
                io::Error::last_os_error()
            );
            let snap = Handle(snap);
            let mut entry = THREADENTRY32 {
                dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
                ..Default::default()
            };
            let mut ok = unsafe { Thread32First(snap.0, &mut entry) };
            let before = seen.len();
            while ok != 0 {
                if entry.th32OwnerProcessID == target.pid && seen.insert(entry.th32ThreadID) {
                    let thread = unsafe {
                        OpenThread(
                            THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION,
                            0,
                            entry.th32ThreadID,
                        )
                    };
                    ensure!(
                        !thread.is_null(),
                        "cannot open a target thread; suspension rolled back"
                    );
                    let thread = Handle(thread);
                    ensure!(
                        unsafe { GetProcessIdOfThread(thread.0) } == target.pid,
                        "thread identity changed"
                    );
                    ensure!(
                        unsafe { WaitForSingleObject(result._process.0, 0) } != WAIT_OBJECT_0,
                        "target exited while opening its threads"
                    );
                    let created = thread_created(&thread)?;
                    let previous = unsafe { SuspendThread(thread.0) };
                    ensure!(previous != u32::MAX, "cannot suspend a target thread");
                    result.threads.push(SuspendedThread {
                        handle: thread,
                        state: ThreadState {
                            id: entry.th32ThreadID,
                            created,
                            previous,
                        },
                    });
                }
                ok = unsafe { Thread32Next(snap.0, &mut entry) };
            }
            if before == seen.len() {
                ensure!(!result.threads.is_empty(), "target has no live threads");
                return Ok(result);
            }
        }
        bail!("target threads changed repeatedly; suspension rolled back")
    }
}
impl Lease for Suspension {
    fn release(&mut self) -> Result<()> {
        let mut failed = Vec::new();
        while let Some(thread) = self.threads.pop() {
            let h = &thread.handle;
            // Only decrement the count we incremented; never resume repeatedly.
            if unsafe { ResumeThread(h.0) } == u32::MAX {
                let mut code = 0;
                if unsafe { GetExitCodeThread(h.0, &mut code) } == 0 || code == 259 {
                    failed.push(thread);
                }
            }
        }
        self.threads = failed;
        ensure!(
            self.threads.is_empty(),
            "some target threads could not be resumed"
        );
        Ok(())
    }
    fn recovery_data(&self) -> serde_json::Value {
        serde_json::json!({"threads": self.threads.iter().map(|t| &t.state).collect::<Vec<_>>()})
    }
}

pub(super) fn recover(target: &ProcessInfo, data: &serde_json::Value) -> Result<()> {
    let _process = open(target, 0)?;
    let threads: Vec<ThreadState> = serde_json::from_value(
        data.get("threads")
            .context("suspension did not record thread identities; manual inspection is required")?
            .clone(),
    )?;
    ensure!(
        threads.len() <= 16_384,
        "invalid suspension recovery record"
    );
    for state in threads {
        let raw = unsafe {
            OpenThread(
                THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION,
                0,
                state.id,
            )
        };
        if raw.is_null() {
            continue;
        } // a terminated thread needs no resume
        let h = Handle(raw);
        if unsafe { GetProcessIdOfThread(h.0) } != target.pid
            || thread_created(&h)? != state.created
        {
            continue;
        }
        // Probe the count, undo that probe, then release at most our own
        // increment. Changed counts are left alone for manual inspection.
        let count = unsafe { SuspendThread(h.0) };
        ensure!(count != u32::MAX, "could not inspect suspension count");
        ensure!(
            unsafe { ResumeThread(h.0) } != u32::MAX,
            "could not undo suspension probe"
        );
        if count == state.previous {
            continue;
        }
        ensure!(
            count == state.previous.saturating_add(1),
            "thread suspension changed outside whohack; refusing to alter another owner's suspension"
        );
        ensure!(
            unsafe { ResumeThread(h.0) } != u32::MAX,
            "could not resume captured thread"
        );
    }
    Ok(())
}
impl Drop for Suspension {
    fn drop(&mut self) {
        let _ = self.release().context("resume on drop");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Backend;
    use std::fs;
    use std::io::{Read, Write};
    use std::os::windows::process::CommandExt;
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    #[test]
    #[ignore = "helper process launched only by the owned-process integration tests"]
    fn owned_helper() {
        let path = std::env::var_os("WHOHACK_TEST_HEARTBEAT").expect("test heartbeat path");
        let input = std::env::var_os("WHOHACK_TEST_INPUT");
        let listeners: Vec<_> = if let Some(output) = std::env::var_os("WHOHACK_TEST_LISTENERS") {
            let listeners: Vec<_> = ["127.0.0.1:0", "[::1]:0"]
                .iter()
                .map(|address| {
                    let listener = std::net::TcpListener::bind(address).unwrap();
                    listener.set_nonblocking(true).unwrap();
                    listener
                })
                .collect();
            let addresses: Vec<_> = listeners.iter().map(|l| l.local_addr().unwrap()).collect();
            fs::write(output, serde_json::to_vec(&addresses).unwrap()).unwrap();
            listeners
        } else {
            vec![]
        };
        let mut streams = Vec::new();
        let mut outbound = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(240);
        while Instant::now() < deadline {
            if let Some(input) = &input {
                // Harmless data repeatedly read by the owned acceptance fixture.
                let _ = fs::read(input).unwrap();
            }
            for listener in &listeners {
                if let Ok((stream, _)) = listener.accept() {
                    stream.set_nonblocking(true).unwrap();
                    streams.push(stream);
                }
            }
            streams.retain_mut(|stream| {
                let mut byte = [0];
                match stream.read(&mut byte) {
                    Ok(1) => stream.write_all(&byte).is_ok(),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => true,
                    _ => false,
                }
            });
            let mut f = fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open(&path)
                .unwrap();
            f.write_all(b".").unwrap();
            if let Ok(address) = std::env::var("WHOHACK_TEST_ADDRESS") {
                let address = address.parse().unwrap();
                if let Ok(stream) =
                    std::net::TcpStream::connect_timeout(&address, Duration::from_millis(100))
                    && std::env::var_os("WHOHACK_TEST_PERSISTENT_CONNECTION").is_some()
                    && outbound.len() < 32
                {
                    outbound.push(stream);
                }
            }
            std::thread::sleep(Duration::from_millis(40));
        }
    }

    #[test]
    #[ignore = "bounded WFP owner helper, launched only by the approved owned-child test"]
    fn owned_wfp_owner() {
        let target: ProcessInfo =
            serde_json::from_str(&std::env::var("WHOHACK_WFP_TARGET").unwrap()).unwrap();
        let lease: Box<dyn crate::Lease> = if std::env::var_os("WHOHACK_TEST_BROKER").is_some() {
            Box::new(super::super::broker::Block::new(&target).unwrap())
        } else {
            super::super::WindowsBackend.block(&target).unwrap()
        };
        assert!(lease.intact().unwrap());
        fs::write(std::env::var_os("WHOHACK_WFP_READY").unwrap(), b"ready").unwrap();
        std::thread::sleep(Duration::from_secs(30));
        drop(lease);
    }
    struct OwnedChild(Child);
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    fn helper(
        dir: &std::path::Path,
        address: Option<std::net::SocketAddr>,
    ) -> (OwnedChild, ProcessInfo) {
        spawn_helper(dir, address, false)
    }
    fn spawn_helper(
        dir: &std::path::Path,
        address: Option<std::net::SocketAddr>,
        listen: bool,
    ) -> (OwnedChild, ProcessInfo) {
        let exe = dir.join("whohack-owned-response-test.exe");
        if !exe.exists() {
            fs::copy(std::env::current_exe().unwrap(), &exe).unwrap();
        }
        let mut cmd = Command::new(&exe);
        cmd.args([
            "--exact",
            "windows::process::tests::owned_helper",
            "--ignored",
            "--nocapture",
        ])
        .env("WHOHACK_TEST_HEARTBEAT", dir.join("heartbeat"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(0x08000000);
        if let Some(address) = address {
            cmd.env("WHOHACK_TEST_ADDRESS", address.to_string());
        }
        if listen {
            cmd.env("WHOHACK_TEST_LISTENERS", dir.join("listeners.json"));
        }
        let child = OwnedChild(cmd.spawn().unwrap());
        let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, child.0.id()) };
        assert!(!raw.is_null());
        let h = Handle(raw);
        let mut times = [FILETIME::default(); 4];
        let [a, b, c, d] = &mut times;
        assert_ne!(unsafe { GetProcessTimes(h.0, a, b, c, d) }, 0);
        let ticks = (u64::from(times[0].dwHighDateTime) << 32) | u64::from(times[0].dwLowDateTime);
        let p = ProcessInfo {
            downloaded_inputs: Vec::new(),
            pid: child.0.id(),
            ppid: std::process::id(),
            start_time: (ticks / 10_000) as i64 - 11_644_473_600_000,
            exe: whohack_core::FileInfo {
                path: exe.to_string_lossy().into(),
                sha256: crate::digest_file(&exe).unwrap(),
                origin: whohack_core::Origin::Unknown,
                sign: whohack_core::SignState::Unsigned,
                yara_hits: vec![],
                first_seen: 1,
            },
            script: None,
            path_class: whohack_core::PathClass::Temp,
            tainted: false,
            taint_root: None,
            app_id: "owned-test".into(),
        };
        wait_until(|| dir.join("heartbeat").exists());
        (child, p)
    }
    fn wait_until(mut ready: impl FnMut() -> bool) {
        wait_until_for(Duration::from_secs(5), &mut ready);
    }
    fn wait_until_for(timeout: Duration, mut ready: impl FnMut() -> bool) {
        let start = Instant::now();
        while !ready() {
            assert!(
                start.elapsed() < timeout,
                "owned helper did not make progress"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    #[test]
    fn owned_child_suspend_resume_stale_identity_and_terminate() {
        let dir = tempfile::tempdir().unwrap();
        let (mut child, p) = helper(dir.path(), None);
        let mut stale = p.clone();
        stale.start_time -= 1;
        assert!(
            terminate(&stale)
                .unwrap_err()
                .to_string()
                .contains("creation time")
        );
        let mut hold = Suspension::new(&p).unwrap();
        let size = fs::metadata(dir.path().join("heartbeat")).unwrap().len();
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(
            fs::metadata(dir.path().join("heartbeat")).unwrap().len(),
            size
        );
        hold.release().unwrap();
        wait_until(|| fs::metadata(dir.path().join("heartbeat")).unwrap().len() > size);
        terminate(&p).unwrap();
        assert!(child.0.wait().unwrap().code().is_some());
    }
    #[test]
    #[ignore = "requires explicit approval and an elevated terminal; changes only temporary WFP filters for a copied test executable"]
    fn wfp_owned_child_block_unblock() {
        exercise_network_block(false);
    }

    #[test]
    #[ignore = "requires Windows consent; only blocks isolated owned test executables"]
    fn wfp_broker_owned_child_block_unblock() {
        exercise_network_block(true);
    }

    #[test]
    #[ignore = "requires Windows consent; inbound and existing flows use only owned loopback helpers"]
    fn wfp_broker_owned_inbound_and_existing_flows() {
        fn connect(address: std::net::SocketAddr) -> std::io::Result<std::net::TcpStream> {
            let stream =
                std::net::TcpStream::connect_timeout(&address, Duration::from_millis(400))?;
            stream.set_read_timeout(Some(Duration::from_millis(400)))?;
            stream.set_write_timeout(Some(Duration::from_millis(400)))?;
            Ok(stream)
        }
        fn exchange(stream: &mut std::net::TcpStream) -> bool {
            let mut byte = [0];
            stream.write_all(b"v").is_ok() && stream.read_exact(&mut byte).is_ok() && byte == *b"v"
        }
        fn reachable(address: std::net::SocketAddr) -> bool {
            connect(address).is_ok_and(|mut stream| exchange(&mut stream))
        }
        fn addresses(dir: &std::path::Path) -> Vec<std::net::SocketAddr> {
            serde_json::from_slice(&fs::read(dir.join("listeners.json")).unwrap()).unwrap()
        }
        let dir = tempfile::tempdir().unwrap();
        let control_dir = tempfile::tempdir().unwrap();
        let (_child, target) = spawn_helper(dir.path(), None, true);
        let (_control, _) = spawn_helper(control_dir.path(), None, true);
        let addresses = addresses(dir.path());
        let controls = serde_json::from_slice::<Vec<std::net::SocketAddr>>(
            &fs::read(control_dir.path().join("listeners.json")).unwrap(),
        )
        .unwrap();
        let mut existing: Vec<_> = addresses.iter().map(|a| connect(*a).unwrap()).collect();
        assert!(existing.iter_mut().all(exchange));
        assert!(controls.iter().all(|a| reachable(*a)));
        let mut block = super::super::broker::Block::new(&target).unwrap();
        assert!(crate::Lease::intact(&block).unwrap());
        assert!(
            addresses.iter().all(|a| !reachable(*a)),
            "new inbound traffic was not blocked"
        );
        assert!(
            controls.iter().all(|a| reachable(*a)),
            "unrelated listener was affected"
        );
        let existing_after_block: Vec<_> = existing.iter_mut().map(exchange).collect();
        crate::Lease::release(&mut block).unwrap();
        wait_until(|| addresses.iter().all(|a| reachable(*a)));
        println!(
            "WFP inbound IPv4/IPv6 and release passed; existing-flow echo after block (observed, not guaranteed): {existing_after_block:?}"
        );
    }

    fn exercise_network_block(broker: bool) {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        };
        struct Server {
            address: std::net::SocketAddr,
            count: Arc<AtomicUsize>,
            stop: Arc<AtomicBool>,
            thread: Option<std::thread::JoinHandle<()>>,
        }
        impl Server {
            fn start(address: &str) -> Self {
                let listener = std::net::TcpListener::bind(address).unwrap();
                let address = listener.local_addr().unwrap();
                listener.set_nonblocking(true).unwrap();
                let count = Arc::new(AtomicUsize::new(0));
                let stop = Arc::new(AtomicBool::new(false));
                let (c, s) = (count.clone(), stop.clone());
                let thread = std::thread::spawn(move || {
                    while !s.load(Ordering::Relaxed) {
                        if listener.accept().is_ok() {
                            c.fetch_add(1, Ordering::SeqCst);
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    }
                });
                Self {
                    address,
                    count,
                    stop,
                    thread: Some(thread),
                }
            }
            fn count(&self) -> usize {
                self.count.load(Ordering::SeqCst)
            }
        }
        impl Drop for Server {
            fn drop(&mut self) {
                self.stop.store(true, Ordering::Relaxed);
                if let Some(thread) = self.thread.take() {
                    let _ = thread.join();
                }
            }
        }
        let v4 = Server::start("127.0.0.1:0");
        let v6 = Server::start("[::1]:0");
        let control = Server::start("127.0.0.1:0");
        let dir = tempfile::tempdir().unwrap();
        let unrelated = tempfile::tempdir().unwrap();
        let (_child4, p) = helper(dir.path(), Some(v4.address));
        let (_child6, _) = helper(dir.path(), Some(v6.address));
        let (_unrelated, _) = helper(unrelated.path(), Some(control.address));
        wait_until(|| v4.count() > 1 && v6.count() > 1 && control.count() > 1);
        let started = Instant::now();
        let mut block: Box<dyn crate::Lease> = if broker {
            Box::new(super::super::broker::Block::new(&p).unwrap())
        } else {
            super::super::WindowsBackend.block(&p).unwrap()
        };
        let elapsed = started.elapsed();
        if super::super::elevated() {
            assert!(elapsed < Duration::from_secs(1), "block took {elapsed:?}");
        }
        assert!(block.intact().unwrap());
        std::thread::sleep(Duration::from_millis(200));
        let before = (v4.count(), v6.count(), control.count());
        std::thread::sleep(Duration::from_millis(400));
        assert_eq!((v4.count(), v6.count()), (before.0, before.1));
        assert!(
            control.count() > before.2,
            "unrelated executable was affected"
        );
        block.release().unwrap();
        wait_until(|| v4.count() > before.0 && v6.count() > before.1);

        let ready = dir.path().join("wfp-owner-ready");
        let mut owner = OwnedChild(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "windows::process::tests::owned_wfp_owner",
                    "--ignored",
                    "--nocapture",
                ])
                .env("WHOHACK_WFP_TARGET", serde_json::to_string(&p).unwrap())
                .env("WHOHACK_WFP_READY", &ready)
                .envs(broker.then_some(("WHOHACK_TEST_BROKER", "1")))
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .creation_flags(0x08000000)
                .spawn()
                .unwrap(),
        );
        let timeout = if broker && !super::super::elevated() {
            Duration::from_secs(110)
        } else {
            Duration::from_secs(5)
        };
        wait_until_for(timeout, || {
            assert!(
                owner.0.try_wait().unwrap().is_none(),
                "WFP owner exited before readiness"
            );
            ready.exists()
        });
        std::thread::sleep(Duration::from_millis(200));
        let before = (v4.count(), v6.count());
        std::thread::sleep(Duration::from_millis(400));
        assert_eq!((v4.count(), v6.count()), before);
        owner.0.kill().unwrap();
        owner.0.wait().unwrap();
        wait_until(|| v4.count() > before.0 && v6.count() > before.1);
        println!(
            "WFP acceptance: IPv4/IPv6, both executable instances, unrelated executable unaffected, release and abrupt-owner cleanup; block_ms={:.3}",
            elapsed.as_secs_f64() * 1000.
        );
    }
}
