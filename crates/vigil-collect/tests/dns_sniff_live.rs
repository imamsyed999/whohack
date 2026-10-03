//! Live DNS sniffer test (Linux, root): a crafted DNS response sent over
//! loopback from port 53 must surface as a `DnsQuery` event. Hermetic, no
//! internet needed. Run with `-- --ignored` as root.
#![cfg(target_os = "linux")]

use std::net::UdpSocket;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use vigil_collect::Collector;
use vigil_collect::linux::dns_sniff::DnsSniffer;
use vigil_core::EventKind;

fn response(qname: &str, v4: [u8; 4]) -> Vec<u8> {
    let mut m = vec![0xab, 0xcd, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
    for label in qname.split('.') {
        m.push(label.len() as u8);
        m.extend_from_slice(label.as_bytes());
    }
    m.push(0);
    m.extend_from_slice(&[0, 1, 0, 1]);
    m.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
    m.extend_from_slice(&v4);
    m
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires root (AF_PACKET)"]
async fn sniffer_reports_dns_answers() {
    DnsSniffer::probe().expect("AF_PACKET socket (are you root?)");
    let sniffer = Arc::new(DnsSniffer);
    let (tx, mut rx) = mpsc::channel(1024);
    let runner = {
        let s = sniffer.clone();
        tokio::spawn(async move { s.run(tx).await })
    };
    tokio::time::sleep(Duration::from_millis(200)).await;

    let server = UdpSocket::bind("127.0.0.2:53").expect("bind 127.0.0.2:53 (root)");
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    let pkt = response("vigil-test.example", [203, 0, 113, 77]);
    server.send_to(&pkt, client.local_addr().unwrap()).unwrap();

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut found = None;
    while Instant::now() < deadline && found.is_none() {
        if let Ok(Some(ev)) = tokio::time::timeout(Duration::from_millis(300), rx.recv()).await
            && let EventKind::DnsQuery { name, answers } = ev.kind
            && name == "vigil-test.example"
        {
            found = Some(answers);
        }
    }
    drop(rx);
    let _ = runner.await;
    assert_eq!(found, Some(vec!["203.0.113.77".parse().unwrap()]));
}
