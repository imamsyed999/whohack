//! Tracepoint `format` file parsing, used to verify the field offsets the
//! eBPF programs were compiled with against the running kernel.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

const TRACEFS_ROOTS: &[&str] = &["/sys/kernel/tracing", "/sys/kernel/debug/tracing"];

/// Parses a tracepoint `format` file into `field name → offset`.
/// `field:__u8 daddr[4];  offset:36;` yields `("daddr", 36)`.
pub fn parse_format(text: &str) -> HashMap<String, usize> {
    let mut out = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("field:") else {
            continue;
        };
        let Some((decl, tail)) = rest.split_once(';') else {
            continue;
        };
        let Some(name) = decl.split_whitespace().last() else {
            continue;
        };
        let name = name.split('[').next().unwrap_or(name);
        let offset = tail
            .split(';')
            .find_map(|kv| kv.trim().strip_prefix("offset:"))
            .and_then(|v| v.trim().parse().ok());
        if let Some(off) = offset {
            out.insert(name.to_string(), off);
        }
    }
    out
}

/// Path of a tracepoint's format file, e.g. `sched/sched_process_exec`.
pub fn format_path(tracepoint: &str) -> Option<PathBuf> {
    TRACEFS_ROOTS
        .iter()
        .map(|r| Path::new(r).join("events").join(tracepoint).join("format"))
        .find(|p| p.exists())
}

/// Checks `(tracepoint, field, expected_offset)` triples against the kernel.
pub fn verify(checks: &[(&str, &str, usize)]) -> Result<(), String> {
    let mut cache: HashMap<&str, HashMap<String, usize>> = HashMap::new();
    for &(tp, field, want) in checks {
        if !cache.contains_key(tp) {
            let path = format_path(tp)
                .ok_or_else(|| format!("tracepoint {tp} not found (is tracefs mounted?)"))?;
            let text =
                std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            cache.insert(tp, parse_format(&text));
        }
        match cache[tp].get(field) {
            Some(&got) if got == want => {}
            Some(&got) => {
                return Err(format!(
                    "{tp}.{field} is at offset {got}, compiled for {want}"
                ));
            }
            None => return Err(format!("{tp} has no field {field}")),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOCK: &str = "name: inet_sock_set_state\nID: 2294\nformat:\n\
\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;\n\
\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;\n\n\
\tfield:const void * skaddr;\toffset:8;\tsize:8;\tsigned:0;\n\
\tfield:int newstate;\toffset:20;\tsize:4;\tsigned:1;\n\
\tfield:__u16 dport;\toffset:26;\tsize:2;\tsigned:0;\n\
\tfield:__u8 daddr[4];\toffset:36;\tsize:4;\tsigned:0;\n\
\tfield:__u8 daddr_v6[16];\toffset:56;\tsize:16;\tsigned:0;\n\n\
print fmt: \"family=%s\"\n";

    const EXEC: &str = "format:\n\tfield:__data_loc char[] filename;\toffset:8;\tsize:4;\tsigned:0;\n\tfield:pid_t pid;\toffset:12;\tsize:4;\tsigned:1;\n";

    #[test]
    fn parses_fields_arrays_pointers_and_data_loc() {
        let f = parse_format(SOCK);
        assert_eq!(f["skaddr"], 8);
        assert_eq!(f["newstate"], 20);
        assert_eq!(f["dport"], 26);
        assert_eq!(f["daddr"], 36);
        assert_eq!(f["daddr_v6"], 56);
        let e = parse_format(EXEC);
        assert_eq!(e["filename"], 8);
        assert_eq!(e["pid"], 12);
    }

    #[test]
    fn compiled_layout_matches_reference_formats() {
        use vigil_ebpf_common_layout_check::*;
        let sock = parse_format(SOCK);
        let exec = parse_format(EXEC);
        for &(tp, field, want) in CHECKS {
            let table = if tp.starts_with("sock/") {
                &sock
            } else {
                &exec
            };
            if let Some(&got) = table.get(field) {
                assert_eq!(got, want, "{tp}.{field}");
            }
        }
    }

    /// The layout constants, mirrored here so this test runs without the
    /// `ebpf` feature (the common crate is only a dependency with it).
    mod vigil_ebpf_common_layout_check {
        pub const CHECKS: &[(&str, &str, usize)] = &[
            ("sched/sched_process_exec", "filename", 8),
            ("sched/sched_process_exec", "pid", 12),
            ("sock/inet_sock_set_state", "newstate", 20),
            ("sock/inet_sock_set_state", "dport", 26),
            ("sock/inet_sock_set_state", "daddr", 36),
            ("sock/inet_sock_set_state", "daddr_v6", 56),
        ];
    }
}
