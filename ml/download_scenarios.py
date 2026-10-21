"""Purpose-specific, inert download behavior exercises for Laya development.

Native offline replay renders every state. No content is downloaded, opened or
executed by this generator. Labels describe authored hypotheses, not measured
malware outcomes. Input extensions are provenance only: the model contract does
not expose them or exercise the application that would decode the content.
"""
import argparse
from collections import Counter, defaultdict
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import random
import subprocess

from dataset import CONTRACT, LABELS, read_jsonl, sha256, validate, write_jsonl
from expanded_scenarios import EXTRA
from security_scenarios import RECIPES
from train_laya import partitions


@dataclass(frozen=True)
class Scenario:
    name: str
    role: str
    categories: str
    behavior: str
    verdict: str
    tactic: str = 'none'
    severity: str = '0'
    action: str = 'allow'
    matches_purpose: str = 'yes'

    @property
    def labels(self):
        return {key: getattr(self, key) for key in LABELS}


def case(name, role, categories, behavior, verdict='benign', tactic='none',
         severity='0', action='allow', matches_purpose=None):
    return Scenario(name, role, categories, behavior, verdict, tactic, severity,
                    action, matches_purpose or ('yes' if verdict == 'benign' else 'no'))


# Selected category/scenario pairs, not a Cartesian product of every category.
# In particular, networking by a player/game is not itself a malicious label.
# Repeated contacts, writes, handle access, or a signature alone cannot establish
# maliciousness. Strong responses below require independent authored signals.
SCENARIOS = [
    case('stream_with_subtitles', 'train', 'media_player', 'read dns tls download small'),
    case('online_match_session', 'train', 'game', 'read udp_game small write'),
    case('launcher_content_patch', 'train', 'game_launcher', 'dns cdn download limited_writes'),
    case('document_export_local', 'train', 'office_document pdf_reader', 'docs write limited_writes'),
    case('archive_extract_small', 'train', 'archive_tool', 'read limited_writes write'),
    case('installer_service_registration', 'train', 'installer_updater', 'dns tls download service write'),
    case('local_media_device', 'train', 'media_player', 'read lan_discovery small'),
    case('browser_login_download', 'train', 'browser', 'browser dns tls small download'),
    case('utility_save_preferences', 'train', 'system_utility other', 'read write limited_writes read'),
    case('regular_https_keepalive', 'train', 'game_launcher chat_messaging', 'read https_poll small'),
    case('unattributed_media_endpoint', 'train', 'media_player pdf_reader', 'read raw small',
         'suspicious', 'none', '1', 'ask_user'),
    case('installer_unconfirmed_autorun', 'train', 'installer_updater', 'read run_key tls small',
         'suspicious', 'persistence', '2', 'ask_user'),
    case('game_overlay_access_only', 'train', 'game', 'read inject udp_game small',
         'suspicious', 'none', '2', 'ask_user'),
    case('media_credentials_no_transfer', 'train', 'media_player pdf_reader', 'read browser write',
         'suspicious', 'credential_theft', '2', 'ask_user'),
    case('unexplained_output_volume', 'train', 'archive_tool office_document', 'read burst write',
         'suspicious', 'ransomware', '2', 'ask_user'),
    case('document_share_unverified', 'train', 'office_document', 'docs tls upload read',
         'suspicious', 'none', '1', 'ask_user', 'yes'),
    case('unsigned_updater_contact', 'train', 'installer_updater', 'dns raw download limited_writes',
         'suspicious', 'none', '1', 'ask_user'),
    case('periodic_media_contact', 'train', 'media_player', 'read https_poll write',
         'suspicious', 'none', '1', 'ask_user'),
    case('media_browser_theft_transfer', 'train', 'media_player', 'read browser inject raw upload write',
         'malicious', 'credential_theft', '3', 'kill_and_quarantine'),
    case('game_wallet_injection_transfer', 'train', 'game', 'udp_game wallet inject port upload',
         'malicious', 'credential_theft', '3', 'kill_and_quarantine'),
    case('reader_mass_rename_injection', 'train', 'pdf_reader office_document', 'docs inject burst run_key',
         'malicious', 'ransomware', '3', 'kill_and_quarantine'),
    case('downloaded_executable_relay', 'train', 'other installer_updater', 'read inject https_poll run_key',
         'malicious', 'command_and_control', '3', 'kill_and_quarantine'),
    case('reader_injected_private_upload', 'train', 'pdf_reader office_document', 'read docs inject port upload write',
         'malicious', 'data_exfiltration', '3', 'block_network'),
    case('downloaded_tool_network_probe', 'train', 'other', 'read inject scan service',
         'malicious', 'reconnaissance', '2', 'block_network'),
    case('hidden_script_autostart_injection', 'train', 'terminal', 'read hidden inject run_key service',
         'malicious', 'persistence', '3', 'kill_and_quarantine'),
    case('archive_memory_theft_channel', 'train', 'archive_tool', 'read lsass inject raw upload',
         'malicious', 'credential_theft', '3', 'kill_and_quarantine'),
    case('music_cache_and_lan', 'select', 'media_player', 'dns lan_discovery download write'),
    case('game_session_and_cache', 'select', 'game', 'dns udp_game small limited_writes'),
    case('installer_registered_service', 'select', 'installer_updater', 'tls download service limited_writes'),
    case('document_save_small', 'select', 'office_document pdf_reader', 'read docs limited_writes'),
    case('unknown_viewer_upload', 'select', 'media_player', 'read port small write',
         'suspicious', 'none', '1', 'ask_user'),
    case('updater_run_key_after_patch', 'select', 'installer_updater', 'limited_writes run_key tls',
         'suspicious', 'persistence', '2', 'ask_user'),
    case('archive_large_rewrite', 'select', 'archive_tool', 'limited_writes read burst',
         'suspicious', 'ransomware', '2', 'ask_user'),
    case('reader_memory_access_uncertain', 'select', 'pdf_reader office_document', 'docs lsass write',
         'suspicious', 'credential_theft', '2', 'ask_user'),
    case('media_keys_persistent_transfer', 'select', 'media_player', 'read ssh run_key port upload',
         'malicious', 'credential_theft', '3', 'kill_and_quarantine'),
    case('game_rewrite_and_injection', 'select', 'game', 'udp_game inject burst service',
         'malicious', 'ransomware', '3', 'kill_and_quarantine'),
    case('archive_injected_tls_poll', 'select', 'archive_tool', 'read inject service https_poll',
         'malicious', 'command_and_control', '3', 'kill_and_quarantine'),
    case('reader_documents_injected_upload', 'select', 'pdf_reader', 'docs write inject raw upload run_key',
         'malicious', 'data_exfiltration', '3', 'block_network'),
    case('video_with_network_cache', 'calibrate', 'media_player', 'read cdn small download limited_writes'),
    case('game_lan_match', 'calibrate', 'game', 'lan_discovery udp_game small read'),
    case('installer_service_after_cache', 'calibrate', 'installer_updater', 'download write service tls'),
    case('archive_roundtrip_limited', 'calibrate', 'archive_tool', 'limited_writes write read'),
    case('player_contact_uncertain', 'calibrate', 'media_player pdf_reader', 'write read raw small',
         'suspicious', 'none', '1', 'ask_user'),
    case('game_unverified_overlay', 'calibrate', 'game', 'udp_game read inject write',
         'suspicious', 'none', '2', 'ask_user'),
    case('media_unexplained_autorun', 'calibrate', 'media_player', 'tls read run_key small',
         'suspicious', 'persistence', '2', 'ask_user'),
    case('document_upload_intent_missing', 'calibrate', 'office_document', 'docs write tls upload',
         'suspicious', 'none', '1', 'ask_user', 'yes'),
    case('game_credentials_relay', 'calibrate', 'game', 'udp_game browser inject https_poll upload',
         'malicious', 'credential_theft', '3', 'kill_and_quarantine'),
    case('media_rename_credential_access', 'calibrate', 'media_player', 'read wallet burst run_key',
         'malicious', 'ransomware', '3', 'kill_and_quarantine'),
    case('script_injected_persistent_poll', 'calibrate', 'terminal', 'hidden read service inject https_poll',
         'malicious', 'command_and_control', '3', 'kill_and_quarantine'),
    case('archive_document_injected_transfer', 'calibrate', 'archive_tool', 'read docs inject tls upload service',
         'malicious', 'data_exfiltration', '3', 'block_network'),
    case('audio_local_and_remote_art', 'test', 'media_player', 'read lan_discovery tls download'),
    case('game_match_then_save', 'test', 'game', 'read small udp_game limited_writes'),
    case('launcher_update_polling', 'test', 'game_launcher', 'https_poll download limited_writes read'),
    case('viewer_export_then_display', 'test', 'office_document pdf_reader', 'docs limited_writes write read'),
    case('archive_extract_and_inspect', 'test', 'archive_tool', 'read limited_writes docs write'),
    case('installer_service_patch', 'test', 'installer_updater', 'cdn limited_writes service read'),
    case('player_unusual_socket', 'test', 'media_player', 'small read port write',
         'suspicious', 'none', '1', 'ask_user'),
    case('viewer_memory_access_only', 'test', 'pdf_reader', 'read lsass dns write',
         'suspicious', 'credential_theft', '2', 'ask_user'),
    case('archive_write_volume_uncertain', 'test', 'archive_tool', 'docs burst limited_writes',
         'suspicious', 'ransomware', '2', 'ask_user'),
    case('game_service_intent_missing', 'test', 'game', 'udp_game service small read',
         'suspicious', 'persistence', '2', 'ask_user'),
    case('media_wallet_theft_with_poll', 'test', 'media_player', 'read wallet inject https_poll upload service',
         'malicious', 'credential_theft', '3', 'kill_and_quarantine'),
    case('reader_memory_rename_attack', 'test', 'pdf_reader office_document', 'docs lsass inject burst',
         'malicious', 'ransomware', '3', 'kill_and_quarantine'),
    case('game_injected_persistent_channel', 'test', 'game', 'udp_game inject run_key https_poll',
         'malicious', 'command_and_control', '3', 'kill_and_quarantine'),
    case('archive_injected_collection', 'test', 'archive_tool', 'limited_writes docs inject port upload service',
         'malicious', 'data_exfiltration', '3', 'block_network'),
    case('downloaded_tool_probe_persistence', 'test', 'other', 'dns service inject scan read',
         'malicious', 'reconnaissance', '2', 'block_network'),
    case('downloaded_script_persistent_injection', 'test', 'terminal', 'hidden docs inject service run_key',
         'malicious', 'persistence', '3', 'kill_and_quarantine'),
]

INPUTS = {
    'media_player': ('mp3', 'mp4', 'wav', 'mkv'), 'office_document': ('docx', 'xlsx', 'pptx'),
    'pdf_reader': ('pdf',), 'archive_tool': ('zip', '7z', 'rar'), 'terminal': ('ps1', 'cmd'),
    'browser': ('html', 'svg'), 'game': ('exe',), 'game_launcher': ('exe',),
    'installer_updater': ('exe', 'msi'), 'system_utility': ('exe',),
    'chat_messaging': ('exe',), 'other': ('exe',),
}
VIEWERS = {'media_player', 'office_document', 'pdf_reader', 'archive_tool', 'browser', 'terminal'}
NAMESPACE = 'whohack-download-behavior-v3'


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def check_recipes(scenarios=SCENARIOS):
    def normalized(behavior):
        return tuple('persist' if token in ('run_key', 'service') else token for token in behavior.split())
    old = {normalized(row[2]) for row in RECIPES + EXTRA}
    seen_names, seen_behaviors = set(), set()
    for scenario in scenarios:
        behavior = normalized(scenario.behavior)
        if scenario.name in seen_names or behavior in seen_behaviors or behavior in old:
            raise ValueError('repeated or previously evaluated behavior recipe')
        if scenario.role not in {'train', 'select', 'calibrate', 'test'}:
            raise ValueError('invalid recipe role')
        if any(category not in INPUTS for category in scenario.categories.split()):
            raise ValueError('unsupported purpose category')
        if any(scenario.labels[qid] not in options for qid, options in LABELS.items()):
            raise ValueError('invalid recipe labels')
        seen_names.add(scenario.name)
        seen_behaviors.add(behavior)


def events(scenario, category, variant, ordinal):
    identity = digest(f'{NAMESPACE}:{scenario.name}:{category}:{variant}')
    rng = random.Random(identity)
    stamp, pid = 1_790_000_000_000 + ordinal * 240_000, 40000 + ordinal
    tokens = scenario.behavior.split()
    name = 'powershell.exe' if 'hidden' in tokens else 'app-' + identity[:10] + '.exe'
    viewer = category in VIEWERS
    file = dict(path='C:/InertFixtures/' + name, sha256=identity,
                origin={'type': 'installed'} if viewer else {'type': 'downloaded', 'url': None, 'referrer': None},
                sign={'type': 'valid_trusted', 'publisher': 'Authored Fixture'} if variant % 2 == 0 else {'type': 'unsigned'},
                yara_hits=[], first_seen=stamp - rng.randint(1, 480) * 3_600_000)
    extension = INPUTS[category][variant % len(INPUTS[category])]
    content = dict(file, path='C:/InertFixtures/Downloads/item.' + extension,
                   sha256=digest(identity + ':input'), origin={'type': 'downloaded', 'url': None, 'referrer': None})
    process = dict(pid=pid, ppid=1, start_time=stamp, exe=file, script=None,
                   path_class='program_files' if viewer else 'downloads',
                   tainted=True, taint_root=pid, app_id=identity,
                   downloaded_inputs=[dict(file=content, observed_at=stamp, read_observed=True)] if viewer else [])
    records, elapsed = [], 0

    def add(kind, delay=6000, **fields):
        nonlocal elapsed
        elapsed += delay
        records.append(dict(event=dict(ts=stamp + elapsed, pid=pid, kind=dict(type=kind, **fields)), process=process))

    def connect(port=443, dns=True, ip='93.184.216.34', proto='tcp'):
        add('net_connect', remote_ip=ip, remote_port=port, proto=proto,
            domain='assets.example' if dns else None, dns_before=dns)

    add('process_start', ppid=1, exe=file['path'],
        cmdline='powershell -WindowStyle Hidden' if 'hidden' in tokens else None)
    if viewer:
        add('file_access', path=content['path'], **{'class': 'other'}, write=False)
    for token in tokens:
        if token == 'hidden':
            continue
        if token in ('read', 'write', 'docs', 'browser', 'ssh', 'wallet', 'lsass'):
            cls = dict(read='other', write='other', docs='documents', browser='browser_passwords',
                       ssh='ssh_keys', wallet='crypto_wallet', lsass='lsass')[token]
            add('file_access', path='C:/InertFixtures/data/item.dat', **{'class': cls}, write=token == 'write')
        elif token == 'dns':
            add('dns_query', name='assets.example', answers=['93.184.216.34'])
        elif token in ('tls', 'raw', 'port'):
            connect(port=4444 if token == 'port' else 443, dns=token == 'tls')
        elif token == 'cdn':
            for ip in ['93.184.216.34', '1.1.1.1', '8.8.8.8']:
                connect(ip=ip)
        elif token == 'udp_game':
            connect(port=27015, dns=True, proto='udp')
            connect(port=27015, dns=True, proto='udp')
        elif token == 'lan_discovery':
            connect(port=1900, dns=False, ip='192.168.1.20', proto='udp')
        elif token == 'https_poll':
            for _ in range(5):
                connect()
        elif token in ('run_key', 'service'):
            add('persistence', location=token, target=file['path'])
        elif token == 'inject':
            add('injection', target_pid=1000 + ordinal)
        elif token in ('burst', 'limited_writes'):
            add('file_burst', modified=rng.randint(180, 500) if token == 'burst' else 12,
                renamed=rng.randint(80, 300) if token == 'burst' else 0, window_ms=10000)
        elif token == 'scan':
            for port in [22, 445, 3389, 5432, 5900, 8088]:
                connect(port=port, dns=False)
        elif token in ('upload', 'download', 'small'):
            up, down = {'upload': (16 * 1024**2, 4096), 'download': (8192, 64 * 1024**2),
                        'small': (8192, 32768)}[token]
            add('net_stats', bytes_up=up, bytes_down=down)
        else:
            raise ValueError('unknown behavior token: ' + token)
    return records, dict(family=NAMESPACE + ':' + scenario.name, role=scenario.role,
                        labels=scenario.labels, app_sha256=identity, recipe=scenario.behavior,
                        category=category, input_extension=extension,
                        input_association='observed_read' if viewer else 'downloaded_executable',
                        phase='after_download_open' if viewer else 'after_download_execute')


def render(service, output, variants=2):
    if not 1 <= variants <= 2:
        raise ValueError('use one or two signature variants; repetition is not independent evidence')
    check_recipes()
    if json.loads(subprocess.check_output([str(service), '--model-contract'], text=True, timeout=30)) != CONTRACT:
        raise ValueError('native serving contract differs')
    output.mkdir(parents=True)
    batches = defaultdict(list)
    ordinal = 0
    for scenario in SCENARIOS:
        for category in scenario.categories.split():
            for variant in range(variants):
                fixture, meta = events(scenario, category, variant, ordinal)
                batches[category].append((fixture, meta))
                ordinal += 1
    rows, catalog = [], []
    for category, cases in batches.items():
        records, ends = [], []
        for fixture, meta in cases:
            records.extend(fixture)
            ends.append((len(records) - 1, meta))
        fixture_path = output / (category + '.jsonl')
        write_jsonl(fixture_path, records)
        result = subprocess.run([str(service), '--replay', str(fixture_path), '--category', category],
                                capture_output=True, text=True, check=True, timeout=120)
        replay = [json.loads(line) for line in result.stdout.splitlines()]
        if len(replay) != len(records):
            raise ValueError('native replay output count mismatch')
        fixture_hash = sha256(fixture_path)
        for index, meta in ends:
            native, role = replay[index], meta['role']
            if not native.get('state'):
                raise ValueError('native replay state missing')
            rows.append(dict(schema_version=1, id=digest(meta['app_sha256'] + ':last'),
                             state=native['state'], feature_vector=native['feature_vector'],
                             feature_names=CONTRACT['features'], questions=CONTRACT['questions'],
                             labels=meta['labels'], source=NAMESPACE + ' (authored simulation)',
                             family=meta['family'], app_sha256=meta['app_sha256'],
                             fixture_sha256=fixture_hash, scorer=native['scorer'], replay_config_sha256=None,
                             split='val' if role in ('select', 'calibrate') else role,
                             validation_role=role if role in ('select', 'calibrate') else None,
                             synthetic=True, review={'accepted': False},
                             scenario_metadata={key: meta[key] for key in
                                                ('recipe', 'category', 'input_extension', 'input_association', 'phase')}))
            catalog.append(dict(fixture=fixture_path.name, event_index=index, **meta))
        print('Rendered', category, len(cases), 'purpose-specific cases', flush=True)
    validate(rows)
    write_jsonl(output / 'dataset.jsonl', rows)
    (output / 'catalog.json').write_text(json.dumps(catalog, indent=2) + '\n', encoding='utf-8')
    return rows


def assert_evaluation_excluded(rows, previous):
    """A renamed ID cannot smuggle a former holdout family, app or state in."""
    excluded = [row for row in previous if row['split'] != 'train']
    for field in ('id', 'family', 'app_sha256', 'state'):
        normalize = str.lower if field == 'app_sha256' else lambda value: value
        protected = {normalize(row[field]) for row in excluded}
        if any(normalize(row[field]) in protected for row in rows):
            raise ValueError('previous evaluation contamination through ' + field)


def same_public_observation(first, second):
    """Permit enrichment of provenance, never a relabel or altered model input.

    A later importer may rename a source family or add a license/repository field.
    The old training row is kept; the same observed event is not counted twice.
    """
    for row in (first, second):
        if (row.get('synthetic') is not False or row.get('split') != 'train'
                or not str(row.get('label_quality', '')).startswith('weak')
                or not row.get('source_sha256') or row.get('source_event_index') is None):
            return False
    fields = ('state', 'labels', 'feature_vector', 'feature_names', 'questions', 'app_sha256',
              'source_sha256', 'source_revision', 'source_path', 'source_event_index',
              'scorer', 'replay_config_sha256', 'validation_role', 'review', 'label_quality')
    return all(first.get(field) == second.get(field) for field in fields)


def merge_rows(previous, fresh, public_groups, exclusions=()):
    validate(previous)
    validate(fresh)
    retained = [row for row in previous if row['split'] == 'train']
    public = []
    for group in public_groups:
        validate(group)
        for row in group:
            if (row['split'] != 'train' or row.get('validation_role') is not None
                    or row.get('synthetic') is not False
                    or not str(row.get('label_quality', '')).startswith('weak')
                    or row.get('review', {}).get('accepted') is not False):
                raise ValueError('public inputs must be unreviewed, nonsynthetic, training-only weak labels')
        public.extend(group)
    candidates = retained + fresh + public
    assert_evaluation_excluded(candidates, previous)
    for excluded in exclusions:
        validate(excluded)
        assert_evaluation_excluded(candidates, excluded)
    rows, by_id, by_state, duplicates = [], {}, {}, 0
    for row in candidates:
        role = row.get('validation_role') if row['split'] == 'val' else row['split']
        if row['id'] in by_id:
            if row != by_id[row['id']] and not same_public_observation(row, by_id[row['id']]):
                raise ValueError('conflicting duplicate case id')
            duplicates += 1
            continue
        if row['state'] in by_state:
            prior = by_state[row['state']]
            prior_role = prior.get('validation_role') if prior['split'] == 'val' else prior['split']
            if row['labels'] != prior['labels'] or role != prior_role:
                raise ValueError('duplicate state has conflicting labels or partitions')
            duplicates += 1
            by_id[row['id']] = row
            continue
        by_id[row['id']] = row
        by_state[row['state']] = row
        rows.append(row)
    groups = partitions(rows)
    for qid, options in LABELS.items():
        if {row['labels'][qid] for row in groups['train']} != set(options):
            raise ValueError('training is missing contract label: ' + qid)
    return rows, duplicates


def main(args):
    output = args.output.resolve()
    if output.exists():
        raise ValueError('use a new output directory; never overwrite training evidence')
    previous = read_jsonl(args.previous)
    public = [read_jsonl(path) for path in args.public]
    exclusions = [read_jsonl(path) for path in args.exclude_evaluation]
    # Fail bad external provenance before performing native replay.
    for group in public:
        validate(group)
        if any(row['split'] != 'train' or not str(row.get('label_quality', '')).startswith('weak')
               or row['synthetic'] or row.get('review', {}).get('accepted') is not False for row in group):
            raise ValueError('public inputs must be unreviewed training-only weak labels')
    fresh = render(args.service.resolve(strict=True), output / 'fresh', args.variants)
    rows, duplicates = merge_rows(previous, fresh, public, exclusions)
    write_jsonl(output / 'dataset.jsonl', rows)
    groups = partitions(rows)
    report = dict(
        qualified=False, cases=len(rows), fresh_authored_cases=len(fresh),
        fresh_authored_families=len(SCENARIOS),
        previous_training_retained=sum(row['split'] == 'train' for row in previous),
        previous_evaluation_excluded=sum(row['split'] != 'train' for row in previous),
        additional_evaluation_exclusions=sum(row['split'] != 'train' for group in exclusions for row in group),
        public_input_cases=sum(map(len, public)), duplicate_input_cases_discarded=duplicates,
        public_weak_label_cases=sum(not row['synthetic'] for row in rows),
        reviewed_cases=sum(row.get('review', {}).get('accepted', False) for row in rows),
        partitions={role: len(group) for role, group in groups.items()},
        labels={qid: dict(Counter(row['labels'][qid] for row in rows)) for qid in LABELS},
        source_hashes={'previous': sha256(args.previous),
                       'public': {str(path): sha256(path) for path in args.public},
                       'excluded_evaluation': {str(path): sha256(path) for path in args.exclude_evaluation}},
        dataset_sha256=sha256(output / 'dataset.jsonl'), service_sha256=sha256(args.service),
        generator_sha256=sha256(Path(__file__)),
        limitations=[
            'Authored labels are hypotheses; no human security review or representative malware evaluation.',
            'Entire authored recipes, application identities and exact states are disjoint across all four roles.',
            'Behavior primitives overlap across roles; signature variants are correlated, not independent samples.',
            'Prior validation/test rows are excluded by ID, family, app identity and exact state.',
            'All real public observations carry provisional weak labels and are used only for training.',
            'Extensions and download association metadata are not exposed in the current model state.',
            'No actual downloaded content, decoder, game, exploit, live sensor or enforcement was exercised.',
            'A network destination, unusual port, periodic contact or signature alone is not proof of malware.',
            'Offline replay uses native built-in category profiles and bootstrap heuristic scores.',
            'Authored kill_and_quarantine labels are development targets; live policy must protect shared viewers.',
        ])
    (output / 'provenance.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report, indent=2))
    return rows


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--service', type=Path, required=True)
    parser.add_argument('--previous', type=Path, required=True)
    parser.add_argument('--public', type=Path, action='append', default=[])
    parser.add_argument('--exclude-evaluation', type=Path, action='append', default=[])
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--variants', type=int, default=2)
    main(parser.parse_args())
