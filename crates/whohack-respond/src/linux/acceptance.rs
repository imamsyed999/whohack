//! Run only in a disposable network namespace; never change the host ruleset.
use super::*;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::Child;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};
use whohack_core::{FileInfo, Origin, PathClass, SignState};

#[test]
#[ignore = "owned helper, invoked only by isolated_network_block_release_and_external_loss"]
fn owned_network_helper() {
    let address: SocketAddr = std::env::var("WHOHACK_RESPONSE_ADDRESS")
        .unwrap()
        .parse()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        let _ = TcpStream::connect_timeout(&address, Duration::from_millis(100));
        std::thread::sleep(Duration::from_millis(40));
    }
}

struct Owned(Child);
impl Drop for Owned {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
struct Server {
    address: SocketAddr,
    count: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Server {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
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
            thread.join().unwrap();
        }
    }
}
fn wait(mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !condition() {
        assert!(
            Instant::now() < deadline,
            "owned network helper made no progress"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}
fn child(path: &Path, server: &Server) -> (Owned, ProcessInfo) {
    fs::copy(std::env::current_exe().unwrap(), path).unwrap();
    let child = Owned(
        Command::new(path)
            .args([
                "--exact",
                "linux::acceptance::owned_network_helper",
                "--ignored",
            ])
            .env("WHOHACK_RESPONSE_ADDRESS", server.address.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let pid = child.0.id();
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    let ticks: i64 = stat
        .rsplit_once(')')
        .unwrap()
        .1
        .split_whitespace()
        .nth(19)
        .unwrap()
        .parse()
        .unwrap();
    let boot: i64 = fs::read_to_string("/proc/stat")
        .unwrap()
        .lines()
        .find_map(|l| l.strip_prefix("btime "))
        .unwrap()
        .parse()
        .unwrap();
    // SAFETY: sysconf has no pointer arguments.
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    let info = ProcessInfo {
        downloaded_inputs: Vec::new(),
        pid,
        ppid: std::process::id(),
        start_time: boot * 1000 + ticks * 1000 / hz,
        exe: FileInfo {
            path: path.to_string_lossy().into(),
            sha256: crate::digest_file(path).unwrap(),
            origin: Origin::Unknown,
            sign: SignState::Unsigned,
            yara_hits: vec![],
            first_seen: 1,
        },
        script: None,
        path_class: PathClass::Temp,
        tainted: false,
        taint_root: None,
        app_id: "owned-network-acceptance".into(),
    };
    (child, info)
}

#[test]
#[ignore = "requires root and a separate network namespace; use tools/linux/test_response.py"]
fn isolated_network_block_release_and_external_loss() {
    assert_eq!(
        std::env::var("WHOHACK_RESPONSE_ISOLATED").as_deref(),
        Ok("1")
    );
    assert_ne!(
        fs::read_link("/proc/self/ns/net").unwrap(),
        fs::read_link("/proc/1/ns/net").unwrap(),
        "refusing to modify the host network namespace"
    );
    let dir = tempfile::tempdir().unwrap();
    let target_server = Server::new();
    let control_server = Server::new();
    let (_owned, target) = child(
        &dir.path().join("whohack-owned-network-test"),
        &target_server,
    );
    let (_control, _) = child(&dir.path().join("whohack-network-control"), &control_server);
    wait(|| target_server.count() > 1 && control_server.count() > 1);
    let mut lease = NetworkBlock::new(&target).unwrap();
    let recovery = lease.recovery_data();
    assert!(lease.intact().unwrap());
    std::thread::sleep(Duration::from_millis(200));
    let before = (target_server.count(), control_server.count());
    std::thread::sleep(Duration::from_millis(400));
    assert_eq!(
        target_server.count(),
        before.0,
        "blocked process still connects"
    );
    assert!(
        control_server.count() > before.1,
        "unrelated process was blocked"
    );
    nft(&format!("delete table inet {}\n", lease.table)).unwrap();
    assert!(
        !lease.intact().unwrap_or(false),
        "external table loss was not detected"
    );
    lease.release().unwrap();
    lease.release().unwrap();
    wait(|| target_server.count() > before.0);
    LinuxBackend
        .recover_release(&target, whohack_core::Action::BlockNetwork, &recovery)
        .unwrap();
    assert!(!lease.group.exists(), "private cgroup was left behind");
    println!(
        "PASS: scoped new-socket block, unaffected control, external table loss, idempotent recovery and cgroup cleanup"
    );
}

#[test]
#[ignore = "requires root and a separate network namespace; tests recovery even without CONFIG_NFT_SOCKET"]
fn isolated_missing_table_recovery() {
    assert_eq!(
        std::env::var("WHOHACK_RESPONSE_ISOLATED").as_deref(),
        Ok("1")
    );
    assert_ne!(
        fs::read_link("/proc/self/ns/net").unwrap(),
        fs::read_link("/proc/1/ns/net").unwrap()
    );
    let dir = tempfile::tempdir().unwrap();
    let server = Server::new();
    let (_owned, target) = child(&dir.path().join("whohack-owned-recovery-test"), &server);
    wait(|| server.count() > 1);
    let original = fs::read_to_string(format!("/proc/{}/cgroup", target.pid)).unwrap();
    let path = original
        .lines()
        .find_map(|l| l.strip_prefix("0::"))
        .unwrap();
    let table = format!("whohack_{:032x}", rand::random::<u128>());
    let group = Path::new("/sys/fs/cgroup").join(&table);
    fs::create_dir(&group).unwrap();
    let mut lease = NetworkBlock {
        target: target.clone(),
        original: Path::new("/sys/fs/cgroup").join(path.trim_start_matches('/')),
        group,
        table,
        installed: false,
    };
    nft(&format!("add table inet {}\n", lease.table)).unwrap();
    lease.installed = true;
    assert!(
        !lease.intact().unwrap(),
        "an empty table cannot protect a process"
    );
    fs::write(lease.group.join("cgroup.procs"), target.pid.to_string()).unwrap();
    let recovery = lease.recovery_data();
    nft(&format!("delete table inet {}\n", lease.table)).unwrap();
    assert!(lease.intact().is_err());
    lease.release().unwrap();
    lease.release().unwrap();
    LinuxBackend
        .recover_release(&target, whohack_core::Action::BlockNetwork, &recovery)
        .unwrap();
    assert_eq!(
        fs::read_to_string(format!("/proc/{}/cgroup", target.pid)).unwrap(),
        original
    );
    assert!(!lease.group.exists());
    println!(
        "PASS: missing table recovery, repeated release, original membership and cgroup cleanup"
    );
}
