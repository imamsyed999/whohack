"""Additional authored boundary cases plus public weak-label telemetry.

The old test/selection/calibration rows are never used for fitting. Only its
training partition is retained. Fresh recipe names are disjoint across all four
roles; they still share behavior primitives, so this is a development evaluation.
"""
import argparse
from collections import Counter
import json
from pathlib import Path

from dataset import LABELS, read_jsonl, sha256, write_jsonl
from security_scenarios import RECIPES, build
from train_laya import partitions

# These labels describe the authored scenario intent, not verified malware.
# Training includes limited evidence that should ask rather than quarantine,
# combinations of threats, and ordinary file/network behavior in all categories.
EXTRA = [
    ('offline_edit', 'train', 'read write read', 'benign', 'none', '0', 'allow'),
    ('media_stream', 'train', 'dns tls download read', 'benign', 'none', '0', 'allow'),
    ('cdn_save', 'train', 'cdn download write', 'benign', 'none', '0', 'allow'),
    ('lan_save', 'train', 'lan small write', 'benign', 'none', '0', 'allow'),
    ('dns_cached', 'train', 'dns tls small', 'benign', 'none', '0', 'allow'),
    ('ordinary_installer', 'train', 'tls download write read', 'benign', 'none', '0', 'allow'),
    ('low_evidence_injection', 'train', 'inject', 'suspicious', 'none', '2', 'ask_user'),
    ('low_evidence_memory_read', 'train', 'lsass', 'suspicious', 'credential_theft', '2', 'ask_user'),
    ('low_evidence_credentials', 'train', 'ssh wallet', 'suspicious', 'credential_theft', '2', 'ask_user'),
    ('autostart_download', 'train', 'tls download persist', 'suspicious', 'persistence', '2', 'ask_user'),
    ('modified_after_download', 'train', 'tls download burst', 'suspicious', 'ransomware', '2', 'ask_user'),
    ('hidden_raw_only', 'train', 'hidden raw', 'suspicious', 'none', '1', 'ask_user'),
    ('injected_wallet_upload', 'train', 'wallet inject raw upload', 'malicious', 'credential_theft', '3', 'kill_and_quarantine'),
    ('browser_ssh_upload', 'train', 'browser ssh raw upload', 'malicious', 'credential_theft', '3', 'kill_and_quarantine'),
    ('write_and_relay', 'train', 'burst inject beacon', 'malicious', 'ransomware', '3', 'kill_and_quarantine'),
    ('hidden_memory_transfer', 'train', 'hidden lsass port upload', 'malicious', 'credential_theft', '3', 'kill_and_quarantine'),
    ('autostart_keychain_transfer', 'train', 'keychain persist raw upload', 'malicious', 'credential_theft', '3', 'kill_and_quarantine'),
    ('injected_docs_tls', 'train', 'docs inject tls upload', 'malicious', 'data_exfiltration', '3', 'block_network'),
    ('injected_scan_autostart', 'train', 'persist inject scan', 'malicious', 'reconnaissance', '2', 'block_network'),
    ('hidden_relay', 'train', 'hidden inject port beacon', 'malicious', 'command_and_control', '3', 'kill_and_quarantine'),
    ('local_copy', 'select', 'write read write', 'benign', 'none', '0', 'allow'),
    ('cdn_play_save', 'select', 'cdn read write download', 'benign', 'none', '0', 'allow'),
    ('lan_copy', 'select', 'read lan small write', 'benign', 'none', '0', 'allow'),
    ('isolated_lsass_after_read', 'select', 'read lsass', 'suspicious', 'credential_theft', '2', 'ask_user'),
    ('injection_without_network', 'select', 'inject write', 'suspicious', 'none', '2', 'ask_user'),
    ('tls_autostart_small', 'select', 'persist tls small', 'suspicious', 'persistence', '2', 'ask_user'),
    ('injected_browser_transfer', 'select', 'browser inject port upload', 'malicious', 'credential_theft', '3', 'kill_and_quarantine'),
    ('mass_write_keychain', 'select', 'burst keychain inject', 'malicious', 'ransomware', '3', 'kill_and_quarantine'),
    ('injected_docs_alt_port', 'select', 'docs inject port upload', 'malicious', 'data_exfiltration', '3', 'block_network'),
    ('autostart_relay_with_read', 'select', 'read hidden persist beacon', 'malicious', 'command_and_control', '3', 'kill_and_quarantine'),
    ('tls_playback', 'calibrate', 'read dns tls download', 'benign', 'none', '0', 'allow'),
    ('lan_export', 'calibrate', 'lan write small read', 'benign', 'none', '0', 'allow'),
    ('cdn_cache', 'calibrate', 'write cdn download read', 'benign', 'none', '0', 'allow'),
    ('isolated_lsass_then_write', 'calibrate', 'lsass write', 'suspicious', 'credential_theft', '2', 'ask_user'),
    ('injection_with_local_read', 'calibrate', 'read inject', 'suspicious', 'none', '2', 'ask_user'),
    ('isolated_autostart_read', 'calibrate', 'read persist', 'suspicious', 'persistence', '2', 'ask_user'),
    ('wallet_keychain_transfer', 'calibrate', 'wallet keychain inject raw upload', 'malicious', 'credential_theft', '3', 'kill_and_quarantine'),
    ('mass_write_with_scan', 'calibrate', 'burst inject scan', 'malicious', 'ransomware', '3', 'kill_and_quarantine'),
    ('docs_injected_autostart_tls', 'calibrate', 'docs persist inject tls upload', 'malicious', 'data_exfiltration', '3', 'block_network'),
    ('injected_relay_with_write', 'calibrate', 'write inject beacon', 'malicious', 'command_and_control', '3', 'kill_and_quarantine'),
    ('offline_roundtrip', 'test', 'read write read write', 'benign', 'none', '0', 'allow'),
    ('dns_stream_cache', 'test', 'dns tls download write read', 'benign', 'none', '0', 'allow'),
    ('cdn_resume_play', 'test', 'read cdn download small', 'benign', 'none', '0', 'allow'),
    ('local_stream_edit', 'test', 'lan small read write read', 'benign', 'none', '0', 'allow'),
    ('isolated_memory_over_tls', 'test', 'lsass tls small', 'suspicious', 'credential_theft', '2', 'ask_user'),
    ('injection_with_dns', 'test', 'dns inject', 'suspicious', 'none', '2', 'ask_user'),
    ('autostart_after_save', 'test', 'write read persist', 'suspicious', 'persistence', '2', 'ask_user'),
    ('modified_after_save', 'test', 'write read burst', 'suspicious', 'ransomware', '2', 'ask_user'),
    ('keychain_ssh_transfer', 'test', 'keychain ssh inject port upload', 'malicious', 'credential_theft', '3', 'kill_and_quarantine'),
    ('mass_write_wallet_autostart', 'test', 'wallet burst persist', 'malicious', 'ransomware', '3', 'kill_and_quarantine'),
    ('docs_transfer_injected_relay', 'test', 'docs inject beacon upload', 'malicious', 'data_exfiltration', '3', 'block_network'),
    ('injected_relay_after_download', 'test', 'tls download inject beacon', 'malicious', 'command_and_control', '3', 'kill_and_quarantine'),
    ('autostart_scan_after_save', 'test', 'write persist inject scan', 'malicious', 'reconnaissance', '2', 'block_network'),
    ('hidden_injected_keys', 'test', 'hidden ssh inject persist', 'malicious', 'persistence', '3', 'kill_and_quarantine'),
]


def main(args):
    if set(r[2] for r in EXTRA) & set(r[2] for r in RECIPES):
        raise ValueError('an old recipe was recycled')
    fresh = build(args.service.resolve(strict=True), args.output / 'fresh',
                  recipes=[('expanded:' + name, *rest) for name, *rest in EXTRA])
    old = read_jsonl(args.previous)
    retained = [row for row in old if row['split'] == 'train']
    public = read_jsonl(args.public)
    if any(row['split'] != 'train' for row in public):
        raise ValueError('public weak labels must not be presented as a trusted holdout')
    rows = retained + fresh + public
    groups = partitions(rows)
    excluded = {r['id'] for r in old if r['split'] != 'train'}
    if excluded & {r['id'] for r in rows}:
        raise ValueError('previous validation/test contamination')
    write_jsonl(args.output / 'dataset.jsonl', rows)
    report = dict(cases=len(rows), previous_training_retained=len(retained),
                  previous_validation_test_excluded=len(excluded), fresh_authored=len(fresh),
                  new_recipes=len(EXTRA), public_weak_label_cases=len(public),
                  source_hashes={key: sha256(path) for key, path in [('previous', args.previous), ('public', args.public)]},
                  partitions={key: len(value) for key, value in groups.items()},
                  labels={q: dict(Counter(r['labels'][q] for r in rows)) for q in LABELS},
                  qualified=False, reviewed_cases=0,
                  test_scope='fresh authored recipes, shared primitives; not independent real-world malware validation')
    (args.output / 'provenance.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['service', 'previous', 'public', 'output']:
        parser.add_argument('--' + name, type=Path, required=True)
    main(parser.parse_args())
