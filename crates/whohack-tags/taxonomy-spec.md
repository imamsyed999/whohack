## 9. Capability tag taxonomy (whohack-tags)

Map every event to zero or more tags. Each tag has a base severity 0–3 and an ATT&CK technique ID where one applies. Store the table in `crates/whohack-tags/src/taxonomy.rs` with unit tests.

- `network:vendor_domain` (0), `network:known_cdn` (0), `network:first_seen_destination` (1), `network:raw_ip_no_dns` (2), `network:unusual_port` (1), `network:intel_hit` (3), `network:beaconing` (3, T1071), `network:large_upload` (2, T1041)
- `exec:script_interpreter` (2, T1059) — powershell, cmd, wscript, cscript, mshta, bash, sh, python, osascript
- `exec:lolbin` (2, T1218) — rundll32, regsvr32, certutil, bitsadmin, curl/wget spawned by a non-shell app
- `exec:hidden_window` (2)
- `exec:child_from_downloads_or_temp` (2)
- `credential_access:browser_passwords` (3, T1555.003), `credential_access:keychain` (3, T1555.001), `credential_access:ssh_keys` (3, T1552.004), `credential_access:crypto_wallets` (3), `credential_access:lsass` (3, T1003.001)
- `persistence:run_key` / `persistence:startup_folder` / `persistence:scheduled_task` / `persistence:service` (Windows), `persistence:launch_agent` / `persistence:login_item` (macOS), `persistence:cron` / `persistence:systemd_unit` / `persistence:shell_rc` (Linux) — all severity 2, T1547/T1053/T1543
- `defense_evasion:av_tamper` (3, T1562), `defense_evasion:log_clear` (3, T1070), `defense_evasion:shadow_copy_delete` (3, T1490)
- `discovery:process_enum` (1, T1057), `discovery:system_info` (1, T1082)
- `collection:screen_capture` (2, T1113), `collection:clipboard` (1, T1115), `collection:keylogging` (3, T1056)
- `impact:mass_file_modification` (3, T1486)
- `injection:remote_thread` (3, T1055)
- `file:read_documents` (0), `file:write_own_dir` (0)

Sensitive path classes (per OS, in config): browser profile credential DBs (Chrome/Edge/Brave `Login Data`, Firefox `logins.json`/`key4.db`), `~/.ssh`, macOS Keychain DBs, common crypto wallet dirs, persistence locations.

---

