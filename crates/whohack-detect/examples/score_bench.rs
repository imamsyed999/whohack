//! Reproducible microbenchmark, not an accuracy evaluation.
use std::sync::Arc;
use std::time::Instant;
use whohack_core::*;
use whohack_detect::window::Windows;
fn main() {
    let p = Arc::new(ProcessInfo {
        downloaded_inputs: Vec::new(),
        pid: 42,
        ppid: 1,
        start_time: 1,
        exe: FileInfo {
            path: "fixture".into(),
            sha256: [1; 32],
            origin: Origin::Unknown,
            sign: SignState::Unsigned,
            yara_hits: vec![],
            first_seen: 0,
        },
        script: None,
        path_class: PathClass::Downloads,
        tainted: true,
        taint_root: None,
        app_id: "fixture".into(),
    });
    let profile = whohack_tags::Profile::from_template(
        whohack_tags::CategoryTemplate::builtin("other").unwrap(),
        None,
    );
    let mut windows = Windows::default();
    let mut latency = Vec::new();
    for ts in 1..=6000 {
        let obs = Observation {
            event: Event {
                ts,
                pid: 42,
                kind: EventKind::NetConnect {
                    remote_ip: "192.0.2.1".parse().unwrap(),
                    remote_port: 443,
                    proto: Proto::Tcp,
                    domain: None,
                    dns_before: false,
                },
            },
            process: Some(p.clone()),
            tags: vec![CapabilityTag::from_static("network:raw_ip_no_dns")],
        };
        let start = Instant::now();
        let score = windows.observe(&obs, &profile).heuristic();
        std::hint::black_box(score);
        if ts > 3000 {
            latency.push(start.elapsed().as_nanos() as f64 / 1000.);
        }
    }
    latency.sort_by(f64::total_cmp);
    println!(
        "{{\"scenario\":\"saturated_2048_event_window\",\"samples\":{},\"p50_us\":{:.3},\"p95_us\":{:.3},\"target_us\":50}}",
        latency.len(),
        latency[latency.len() / 2],
        latency[latency.len() * 95 / 100]
    );
}
