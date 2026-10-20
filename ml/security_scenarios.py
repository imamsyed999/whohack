"""Harmless synthetic behavior fixtures, rendered by native whohack replay.

No files named in events are opened, no programs are launched from fixtures, and
no network destinations are contacted. Labels are authored simulation hypotheses,
not human-reviewed observations. Entire behavior recipes stay in one partition.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import random
import subprocess

from dataset import CONTRACT, LABELS, sha256, validate, write_jsonl

CATEGORIES = ('browser office_document pdf_reader media_player game game_launcher '
              'chat_messaging developer_tool ide terminal system_utility '
              'driver_or_hardware_tool vpn_or_network_tool security_tool '
              'installer_updater archive_tool password_manager crypto_wallet other').split()

# Family, partition, behavior recipe, verdict, tactic, severity, action.
# Selection validation and calibration use distinct recipe families as well.
RECIPES = [
    ('local_read', 'train', 'read', 'benign', 'none', '0', 'allow'),
    ('normal_download', 'train', 'tls download', 'benign', 'none', '0', 'allow'),
    ('dns_lookup', 'train', 'dns', 'benign', 'none', '0', 'allow'),
    ('local_network', 'train', 'lan small', 'benign', 'none', '0', 'allow'),
    ('ordinary_save', 'train', 'write', 'benign', 'none', '0', 'allow'),
    ('tls_exchange', 'train', 'tls small', 'benign', 'none', '0', 'allow'),
    ('new_port', 'train', 'port', 'suspicious', 'none', '1', 'ask_user'),
    ('no_dns', 'train', 'raw', 'suspicious', 'none', '1', 'ask_user'),
    ('regular_unknown', 'train', 'beacon', 'suspicious', 'command_and_control', '2', 'ask_user'),
    ('new_autostart', 'train', 'persist', 'suspicious', 'persistence', '2', 'ask_user'),
    ('unexplained_mass_write', 'train', 'burst', 'suspicious', 'ransomware', '2', 'ask_user'),
    ('unknown_large_upload', 'train', 'raw upload', 'suspicious', 'data_exfiltration', '2', 'ask_user'),
    ('port_fanout', 'train', 'scan', 'suspicious', 'reconnaissance', '2', 'ask_user'),
    ('browser_autostart_exfil', 'train', 'browser persist raw upload', 'malicious', 'credential_theft', '3', 'kill_and_quarantine'),
    ('ssh_injection_exfil', 'train', 'ssh inject raw upload', 'malicious', 'credential_theft', '3', 'kill_and_quarantine'),
    ('lsass_external_upload', 'train', 'lsass raw upload', 'malicious', 'credential_theft', '3', 'kill_and_quarantine'),
    ('mass_write_autostart', 'train', 'persist burst raw', 'malicious', 'ransomware', '3', 'kill_and_quarantine'),
    ('mass_write_injection', 'train', 'inject burst', 'malicious', 'ransomware', '3', 'kill_and_quarantine'),
    ('injected_regular_channel', 'train', 'inject beacon', 'malicious', 'command_and_control', '3', 'kill_and_quarantine'),
    ('hidden_persistent_channel', 'train', 'hidden persist beacon', 'malicious', 'command_and_control', '3', 'kill_and_quarantine'),
    ('injected_document_upload', 'train', 'docs inject raw upload', 'malicious', 'data_exfiltration', '3', 'block_network'),
    ('injected_port_scan', 'train', 'inject scan', 'malicious', 'reconnaissance', '2', 'block_network'),
    ('hidden_injected_autostart', 'train', 'hidden inject persist', 'malicious', 'persistence', '3', 'kill_and_quarantine'),
    ('multi_cdn_download', 'select', 'cdn download', 'benign', 'none', '0', 'allow'),
    ('document_tls_read', 'select', 'docs tls', 'benign', 'none', '0', 'allow'),
    ('mass_write_with_tls', 'select', 'burst tls', 'suspicious', 'ransomware', '2', 'ask_user'),
    ('autostart_with_dns', 'select', 'persist dns', 'suspicious', 'persistence', '2', 'ask_user'),
    ('wallet_autostart_upload', 'select', 'wallet persist port upload', 'malicious', 'credential_theft', '3', 'kill_and_quarantine'),
    ('mass_write_credential_access', 'select', 'browser burst', 'malicious', 'ransomware', '3', 'kill_and_quarantine'),
    ('hidden_injected_channel', 'select', 'hidden inject beacon', 'malicious', 'command_and_control', '3', 'kill_and_quarantine'),
    ('local_read_save', 'calibrate', 'read write', 'benign', 'none', '0', 'allow'),
    ('download_then_read', 'calibrate', 'tls download read', 'benign', 'none', '0', 'allow'),
    ('unusual_port_upload', 'calibrate', 'port small', 'suspicious', 'none', '1', 'ask_user'),
    ('autostart_with_tls', 'calibrate', 'persist tls', 'suspicious', 'persistence', '2', 'ask_user'),
    ('keychain_injected_upload', 'calibrate', 'keychain inject port upload', 'malicious', 'credential_theft', '3', 'kill_and_quarantine'),
    ('persistent_document_upload', 'calibrate', 'docs persist raw upload', 'malicious', 'data_exfiltration', '3', 'block_network'),
    ('mass_write_with_hidden_injection', 'calibrate', 'hidden inject burst', 'malicious', 'ransomware', '3', 'kill_and_quarantine'),
    ('local_network_read', 'test', 'lan read small', 'benign', 'none', '0', 'allow'),
    ('dns_and_local_write', 'test', 'dns write', 'benign', 'none', '0', 'allow'),
    ('multi_cdn_read', 'test', 'cdn read', 'benign', 'none', '0', 'allow'),
    ('new_port_after_read', 'test', 'read port', 'suspicious', 'none', '1', 'ask_user'),
    ('fanout_after_local_write', 'test', 'write scan', 'suspicious', 'reconnaissance', '2', 'ask_user'),
    ('wallet_injected_channel', 'test', 'wallet inject beacon', 'malicious', 'credential_theft', '3', 'kill_and_quarantine'),
    ('mass_write_and_lsass', 'test', 'lsass burst', 'malicious', 'ransomware', '3', 'kill_and_quarantine'),
    ('persistent_injected_channel', 'test', 'persist inject beacon', 'malicious', 'command_and_control', '3', 'kill_and_quarantine'),
    ('hidden_document_exfil', 'test', 'docs hidden raw upload persist', 'malicious', 'data_exfiltration', '3', 'block_network'),
    ('credential_autostart', 'test', 'browser ssh persist', 'malicious', 'persistence', '3', 'kill_and_quarantine'),
]


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


def events(recipe, category, variant, ordinal):
    family, role, actions, verdict, tactic, severity, action = recipe
    identity = digest(f'whohack-sim-v2:{family}:{category}:{variant}')
    rng = random.Random(identity)
    pid = 20000 + ordinal
    stamp = 1_770_000_000_000 + ordinal * 240_000
    signed = rng.choice([True, False])  # Independent of the label.
    downloaded = rng.choice([True, False])
    path_class = rng.choice(['downloads', 'temp']) if downloaded else 'program_files'
    name = 'powershell.exe' if 'hidden' in actions.split() else 'app-' + identity[:10] + '.exe'
    path = 'C:/Synthetic/' + name
    file = dict(path=path, sha256=identity,
                origin=dict(type='downloaded', url=None, referrer=None) if downloaded else dict(type='installed'),
                sign=dict(type='valid_trusted', publisher='Synthetic Fixture') if signed else dict(type='unsigned'),
                yara_hits=[], first_seen=stamp - rng.randint(0, 720) * 3_600_000)
    # Content type is metadata only. The current decision state does not decode
    # media or expose input filenames; this must not be described as media testing.
    extension = rng.choice(['mp4', 'mp3', 'pdf', 'docx', 'zip', 'exe', 'ps1', 'jpg'])
    content = dict(file, path='C:/Synthetic/Downloads/item.' + extension,
                   sha256=digest(identity + ':input'), origin=dict(type='downloaded', url=None, referrer=None))
    process = dict(pid=pid, ppid=1, start_time=stamp, exe=file, script=None,
                   path_class=path_class, tainted=True, taint_root=pid, app_id=identity,
                   downloaded_inputs=[dict(file=content, observed_at=stamp, read_observed=True)])
    result = []
    def add(kind, **kw):
        result.append(dict(event=dict(ts=stamp + len(result) * 6000, pid=pid,
                                      kind=dict(type=kind, **kw)), process=process))
    add('process_start', ppid=1, exe=path, cmdline='powershell -WindowStyle Hidden' if 'hidden' in actions.split() else None)
    # Public IP values below are inert fixture strings; replay never opens sockets.
    def net(port=443, dns=True, ip='93.184.216.34'):
        add('net_connect', remote_ip=ip, remote_port=port, proto='tcp',
            domain='assets.example' if dns else None, dns_before=dns)
    for token in actions.split():
        if token == 'hidden':
            continue
        if token in ('read', 'write', 'docs', 'browser', 'ssh', 'wallet', 'lsass', 'keychain'):
            cls = dict(read='other', write='other', docs='documents', browser='browser_passwords',
                       ssh='ssh_keys', wallet='crypto_wallet', lsass='lsass', keychain='keychain')[token]
            add('file_access', path='C:/Synthetic/data/item.dat', **{'class': cls}, write=token == 'write')
        elif token == 'dns':
            add('dns_query', name='assets.example', answers=['93.184.216.34'])
        elif token == 'tls':
            net()
        elif token == 'raw':
            net(dns=False)
        elif token == 'port':
            net(port=rng.choice([4444, 8088, 8443, 9001]), dns=False)
        elif token == 'lan':
            net(port=443, ip='192.168.1.15', dns=False)
        elif token == 'cdn':
            for ip in ['93.184.216.34', '1.1.1.1', '8.8.8.8']:
                net(ip=ip)
        elif token == 'beacon':
            for _ in range(5):
                net(port=4444, dns=False)
        elif token == 'scan':
            for port in [22, 445, 3389, 5432, 5900, 8088]:
                net(port=port, dns=False)
        elif token == 'persist':
            add('persistence', location=rng.choice(['run_key', 'startup_folder', 'scheduled_task', 'service']), target=path)
        elif token == 'inject':
            add('injection', target_pid=1000 + ordinal)
        elif token == 'burst':
            add('file_burst', modified=rng.randint(150, 600), renamed=rng.randint(50, 400), window_ms=10000)
        elif token in ('upload', 'download', 'small'):
            up, down = {'upload': (rng.randint(8, 40) * 1024**2, 1024),
                        'download': (4096, rng.randint(10, 500) * 1024**2),
                        'small': (rng.randint(1, 40) * 1024, rng.randint(1, 40) * 1024)}[token]
            add('net_stats', bytes_up=up, bytes_down=down)
        else:
            raise ValueError(token)
    labels = dict(matches_purpose='yes' if verdict == 'benign' else 'no',
                  verdict=verdict, tactic=tactic, severity=severity, action=action)
    return result, dict(family=family, role=role, labels=labels, app_sha256=identity,
                        input_extension=extension, recipe=actions)


def build(service, output, variants=1, recipes=None):
    recipes = RECIPES if recipes is None else recipes
    if not 1 <= variants <= 4:
        raise ValueError('use one to four variants; repetition is not independent evidence')
    if output.exists():
        raise ValueError('use a new output directory')
    if json.loads(subprocess.check_output([str(service), '--model-contract'], text=True, timeout=30)) != CONTRACT:
        raise ValueError('native serving contract differs')
    output.mkdir(parents=True)
    rows, catalog, ordinal = [], [], 0
    for category in CATEGORIES:
        records, ends = [], []
        for recipe in recipes:
            for variant in range(variants):
                fixture, meta = events(recipe, category, variant, ordinal)
                ordinal += 1
                records.extend(fixture)
                ends.append((len(records) - 1, meta))
        fixture_path = output / (category + '.jsonl')
        write_jsonl(fixture_path, records)
        run = subprocess.run([str(service), '--replay', str(fixture_path), '--category', category],
                             capture_output=True, text=True, check=True, timeout=120)
        replay = [json.loads(line) for line in run.stdout.splitlines()]
        if len(replay) != len(records):
            raise ValueError('native replay output count mismatch')
        fixture_hash = sha256(fixture_path)
        for index, meta in ends:
            r = replay[index]
            if not r.get('state'):
                raise ValueError('native state missing')
            role = meta['role']
            rows.append(dict(schema_version=1, id=digest(meta['app_sha256'] + ':last'),
                             state=r['state'], feature_vector=r['feature_vector'],
                             feature_names=CONTRACT['features'], questions=CONTRACT['questions'],
                             labels=meta['labels'], source='whohack-security-scenarios-v2 (authored simulation)',
                             family=meta['family'], app_sha256=meta['app_sha256'],
                             fixture_sha256=fixture_hash, scorer=r['scorer'], replay_config_sha256=None,
                             split='val' if role in ('select', 'calibrate') else role,
                             validation_role=role if role in ('select', 'calibrate') else None,
                             synthetic=True, review=dict(accepted=False)))
            catalog.append(dict(fixture=fixture_path.name, event_index=index, category=category, **meta))
        print('Rendered', category, len(ends), 'cases', flush=True)
    validate(rows)
    write_jsonl(output / 'dataset.jsonl', rows)
    (output / 'catalog.json').write_text(json.dumps(catalog, indent=2) + '\n', encoding='utf-8')
    report = dict(cases=len(rows), families=len(recipes), synthetic=True, reviewed_cases=0,
                  service_sha256=sha256(service), generator_sha256=sha256(Path(__file__)),
                  dataset_sha256=sha256(output / 'dataset.jsonl'),
                  splits=dict(Counter(r['split'] for r in rows)),
                  labels={q: dict(Counter(r['labels'][q] for r in rows)) for q in LABELS},
                  limitations=['Authored labels are hypotheses, not reviewed security ground truth.',
                               'Recipe families are disjoint; primitives still overlap across splits.',
                               'No actual media decoding, exploit execution, or sensor acceptance is measured.',
                               'Fixed category templates and bootstrap scorer; no live user telemetry.'])
    (output / 'provenance.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report, indent=2))
    return rows


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--service', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--variants', type=int, default=1)
    a = p.parse_args()
    build(a.service.resolve(strict=True), a.output.resolve(), a.variants)
