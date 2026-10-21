"""Import pinned public Sysmon *text*, never execute any recorded command.

Only windows with observable credential-read, persistence or injection evidence
receive provisional suspicious/ask labels. Absence of those signals is NOT a
benign label. A malware dataset folder is NOT a process verdict. Unsupported
events, absent byte counts/signatures/origin, and inferred identities stay explicit.
"""
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from pathlib import Path, PureWindowsPath
import re
import subprocess
import xml.etree.ElementTree as ET

from dataset import CONTRACT, sha256, validate, write_jsonl

NS = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def parse_line(line):
    if len(line) > 1_048_576 or '<!DOCTYPE' in line or '<!ENTITY' in line:
        raise ValueError('oversized XML or entity declaration')
    event = ET.fromstring(line)
    provider = event.find('e:System/e:Provider', NS)
    if provider is None or provider.get('Name') != 'Microsoft-Windows-Sysmon':
        return None
    data = {d.get('Name'): d.text or '' for d in event.findall('e:EventData/e:Data', NS)}
    number = int(event.find('e:System/e:EventID', NS).text)
    stamp = data.get('UtcTime') or event.find('e:System/e:TimeCreated', NS).get('SystemTime')
    parsed = datetime.fromisoformat(stamp.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    data['_ts'] = int(parsed.timestamp() * 1000)
    return number, data


def normal_path(path):
    return re.sub(r'\\+', '/', path).lower()


def persistence(target):
    path = normal_path(target)
    if re.search(r'/software/(?:wow6432node/)?microsoft/windows/currentversion/run(?:once)?/[^/]+$', path):
        return 'run_key'
    if '/start menu/programs/startup/' in path:
        return 'startup_folder'
    if re.search(r'/system/(?:currentcontrolset|controlset\d+)/services/[^/]+/imagepath$', path):
        return 'service'
    return None


def observed_kind(number, data, dns):
    if number == 1:
        return dict(type='process_start', ppid=int(data.get('ParentProcessId', 0)),
                    exe=data.get('Image', ''), cmdline=data.get('CommandLine'))
    if number == 22:
        answers = []
        for token in re.split(r'[;,\s]+', data.get('QueryResults', '')):
            try:
                address = str(ipaddress.ip_address(token))
                answers.append(address)
                dns[address] = (data['_ts'], data.get('QueryName', ''))
            except ValueError:
                pass
        return dict(type='dns_query', name=data.get('QueryName', ''), answers=answers)
    if number == 3:
        address = str(ipaddress.ip_address(data['DestinationIp']))
        port = int(data['DestinationPort'])
        protocol = data.get('Protocol', '').lower()
        if not 0 <= port <= 65535 or protocol not in ('tcp', 'udp'):
            return None
        prior = dns.get(address)
        before = bool(prior and 0 <= data['_ts'] - prior[0] <= 300_000)
        # DestinationHostname alone does not prove a preceding DNS answer.
        return dict(type='net_connect', remote_ip=address, remote_port=port,
                    proto=protocol, domain=prior[1] if before else None, dns_before=before)
    if number == 8:
        return dict(type='injection', target_pid=int(data['TargetProcessId']))
    if number == 10:
        # Query-limited (0x1000) alone is not a memory read or credential access.
        mask = int(data.get('GrantedAccess', '0'), 16)
        if normal_path(data.get('TargetImage', '')).endswith('/lsass.exe') and mask & 0x10:
            return dict(type='file_access', path='observed:lsass-process-memory',
                        **{'class': 'lsass'}, write=False)
    if number == 11:
        location = persistence(data.get('TargetFilename', ''))
        if location:
            return dict(type='persistence', location=location, target=data['TargetFilename'])
        return dict(type='file_access', path=data.get('TargetFilename', ''), **{'class': 'other'}, write=True)
    # Only a set-value event proves a write. Registry enumeration/deletion is
    # not silently converted to persistence, and deleted files are not writes.
    if number == 13:
        location = persistence(data.get('TargetObject', ''))
        if location:
            return dict(type='persistence', location=location, target=data.get('Details', 'unknown'))
    return None


def provisional_labels(state):
    # Use evidence still present in the rendered time window, not stale signals
    # from earlier in this process's trace. No malware-folder name enters here.
    if 'credential_access:lsass' in state or 'sensitive=lsass' in state:
        tactic = 'credential_theft'
    elif re.search(r'^PERSIST (?!none)', state, re.M):
        tactic = 'persistence'
    elif 'injection:remote_thread' in state:
        tactic = 'none'
    else:
        return None
    return dict(matches_purpose='no', verdict='suspicious', tactic=tactic,
                severity='2', action='ask_user')


def validate_acquisition(acquisition):
    """Reject unsafe or ambiguous local namespaces before writing fixtures."""
    if (acquisition.get('repository') != 'splunk/attack_data'
            or not re.fullmatch(r'[0-9a-f]{40}', acquisition.get('revision', ''))
            or acquisition.get('license') != 'Apache-2.0'):
        raise ValueError('unsupported acquisition provenance')
    families, files, paths = set(), set(), set()
    for entry in acquisition['files']:
        family, file = entry['family'], entry['file']
        if (not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', family)
                or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,199}\.log', file)
                or PureWindowsPath(family + '.jsonl').is_reserved()
                or PureWindowsPath(file).is_reserved()
                or '..' in Path(entry['source_path']).parts
                or not re.fullmatch(r'datasets/(?:malware|attack_techniques)/[A-Za-z0-9_./-]+\.log', entry['source_path'])):
            raise ValueError('unsafe acquisition filename or source path')
        if (family.lower() in families or file.lower() in files or entry['source_path'].lower() in paths):
            raise ValueError('ambiguous acquisition namespace')
        if (type(entry['bytes']) is not int or not 0 < entry['bytes'] <= 30_000_000
                or not re.fullmatch(r'[0-9a-f]{64}', entry['sha256'])):
            raise ValueError('invalid acquisition size or digest')
        families.add(family.lower())
        files.add(file.lower())
        paths.add(entry['source_path'].lower())


def build(source, service, output):
    if output.exists():
        raise ValueError('use a new output directory')
    acquisition = json.loads((source / 'acquisition.json').read_text())
    validate_acquisition(acquisition)
    if json.loads(subprocess.check_output([str(service), '--model-contract'], text=True)) != CONTRACT:
        raise ValueError('serving contract mismatch')
    output.mkdir(parents=True)
    rows, counts, selected, total_windows = [], Counter(), Counter(), 0
    source_reports, all_states = [], set()
    for entry in acquisition['files']:
        selected[entry['family']] = 0
        path = (source / entry['file']).resolve()
        if not path.is_relative_to(source.resolve()):
            raise ValueError('source file escapes acquisition directory')
        if path.stat().st_size != entry['bytes'] or sha256(path) != entry['sha256']:
            raise ValueError('source digest mismatch')
        processes = defaultdict(list)
        for line in path.open(encoding='utf-8-sig'):
            try:
                parsed = parse_line(line)
            except (ET.ParseError, ValueError, AttributeError, KeyError):
                counts['malformed'] += 1
                continue
            if parsed is None:
                counts['unsupported_provider'] += 1
                continue
            number, data = parsed
            counts['sysmon_' + str(number)] += 1
            guid = data.get('SourceProcessGUID', data.get('SourceProcessGuid')) if number in (8, 10) else data.get('ProcessGuid', data.get('ProcessGUID'))
            image = data.get('SourceImage') if number in (8, 10) else data.get('Image')
            if not guid or not image:
                counts['without_process_identity'] += 1
                continue
            processes[(guid.lower(), normal_path(image))].append((number, data))
        records, ends = [], {}
        for ordinal, ((guid, path_name), events) in enumerate(sorted(processes.items())):
            events.sort(key=lambda pair: pair[1]['_ts'])
            start = next((d for n, d in events if n == 1), None)
            process_digest = None
            if start:
                match = re.search(r'(?:^|,)SHA256=([0-9a-fA-F]{64})(?:,|$)', start.get('Hashes', ''))
                if match:
                    process_digest = match[1].lower()
            # Explicitly synthetic identity if no process-start image hash was
            # recorded; a FileDelete hash belongs to its target, not the process.
            identity = process_digest or digest('unverified-public-image:' + path_name)
            stamp = start['_ts'] if start else events[0][1]['_ts']
            pid = 100_000 + ordinal
            # Neutral display names prevent malware filenames being label hints.
            name = path_name.rsplit('/', 1)[-1]
            display_name = name if name in ('powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe') else 'observed-' + identity[:10] + '.exe'
            file = dict(path='C:/PublicReplay/' + display_name, sha256=identity,
                        origin=dict(type='unknown'), sign=dict(type='unsigned'),
                        yara_hits=[], first_seen=stamp)
            process = dict(pid=pid, ppid=0, start_time=stamp, exe=file, script=None,
                           path_class='other', tainted=False, taint_root=None,
                           app_id=identity, downloaded_inputs=[])
            dns, last_bucket, last_index, immediate_types = {}, None, None, set()
            for number, data in events:
                try:
                    kind = observed_kind(number, data, dns)
                except (ValueError, KeyError):
                    counts['invalid_supported_event'] += 1
                    continue
                if not kind:
                    continue
                if kind['type'] == 'process_start':
                    kind['exe'] = file['path']
                    kind['ppid'] = 0
                bucket = data['_ts'] // 60_000
                if last_bucket is not None and bucket != last_bucket:
                    ends[last_index] = (identity, process_digest is not None)
                    immediate_types.clear()
                records.append(dict(event=dict(ts=data['_ts'], pid=pid, kind=kind), process=process))
                last_index, last_bucket = len(records) - 1, bucket
                # Keep the first newly observed concerning behavior in each
                # minute as well as the minute endpoint. This preserves early
                # response examples without adding a label to quiet windows.
                signal = kind['type'] if kind['type'] in ('persistence', 'injection') else (
                    'lsass_handle_read_permission' if kind.get('class') == 'lsass' else None)
                if signal and signal not in immediate_types:
                    ends[last_index] = (identity, process_digest is not None)
                    immediate_types.add(signal)
            if last_index is not None:
                ends[last_index] = (identity, process_digest is not None)
        if not records:
            source_reports.append(dict(source_path=entry['source_path'], source_sha256=entry['sha256'],
                                       candidates=0, selected=0, unlabeled=0, duplicate_states=0))
            continue
        fixture = output / (entry['family'] + '.jsonl')
        write_jsonl(fixture, records)
        fixture_digest = sha256(fixture)
        # Replay can expand a small source log substantially. Keep its output on
        # disk and retain only requested windows, rather than all model states.
        replay_path = output / 'replay-working.jsonl'
        with replay_path.open('wb') as replay_file:
            subprocess.run([str(service), '--replay', str(fixture), '--category', 'other'],
                           stdout=replay_file, stderr=subprocess.PIPE, check=True, timeout=180)
        replay, replay_count = {}, 0
        with replay_path.open(encoding='utf-8') as replay_file:
            for index, line in enumerate(replay_file):
                replay_count += 1
                if index in ends:
                    replay[index] = json.loads(line)
        replay_path.unlink()
        if replay_count != len(records):
            raise ValueError('replay output count mismatch')
        unlabeled, duplicates = 0, 0
        for index, (identity, verified) in sorted(ends.items()):
            total_windows += 1
            result = replay[index]
            state = result.get('state')
            labels = provisional_labels(state) if state else None
            if not labels:
                unlabeled += 1
                continue
            if state in all_states:
                duplicates += 1
                continue
            all_states.add(state)
            # Public traces are weak-label training data ONLY. No accuracy claim
            # uses them as a trusted holdout; shared background binaries cannot
            # accidentally cross from training into a public test partition.
            rows.append(dict(schema_version=1, id=digest(entry['sha256'] + ':' + str(index)),
                             state=state, feature_vector=result['feature_vector'],
                             feature_names=CONTRACT['features'], questions=CONTRACT['questions'],
                             labels=labels, source='Splunk attack_data; provisional evidence labels',
                             family='splunk:' + entry['family'], app_sha256=identity,
                             identity_is_recorded_image_hash=verified,
                             fixture_sha256=fixture_digest, source_sha256=entry['sha256'],
                             source_revision=acquisition['revision'], source_path=entry['source_path'],
                             source_repository=acquisition['repository'], source_license=acquisition['license'],
                             source_context=entry.get('source_context', 'public lab trace; includes background processes'),
                             source_technique=entry.get('technique'), source_technique_is_label=False,
                             source_event_index=index, scorer=result['scorer'], replay_config_sha256=None,
                             split='train', validation_role=None, synthetic=False,
                             label_quality='weak_observable_behavior', review=dict(accepted=False),
                             missing_fields=['signature (unsigned placeholder)', 'download origin',
                                             'network byte counts', 'verified start time when absent']))
            selected[entry['family']] += 1
        source_reports.append(dict(source_path=entry['source_path'], source_sha256=entry['sha256'],
                                   candidates=len(ends), selected=selected[entry['family']],
                                   unlabeled=unlabeled, duplicate_states=duplicates))
        print('Imported', entry['family'], selected[entry['family']], 'provisional cases', flush=True)
    validate(rows)
    write_jsonl(output / 'dataset.jsonl', rows)
    report = dict(cases=len(rows), observed_windows=total_windows, families=dict(selected), events=dict(counts),
                  sources=len(acquisition['files']), sources_with_selected_cases=sum(v > 0 for v in selected.values()),
                  skipped_unlabeled_windows=sum(s['unlabeled'] for s in source_reports),
                  skipped_duplicate_states=sum(s['duplicate_states'] for s in source_reports),
                  label_counts=dict(Counter(r['labels']['tactic'] for r in rows)), source_reports=source_reports,
                  acquisition_sha256=sha256(source / 'acquisition.json'), importer_sha256=sha256(Path(__file__)),
                  service_sha256=sha256(service), dataset_sha256=sha256(output / 'dataset.jsonl'),
                  reviewed_cases=0, license='Apache-2.0', qualified=False,
                  limitations=['All public rows are training-only provisional suspicious labels.',
                               'Other windows remain unlabeled; no clean verdict inferred from missing signals.',
                               'Sysmon source visibility differs from native ETW; import does not add sensors.',
                               'Unknown signatures use the existing unsigned schema placeholder.',
                               'LSASS handle memory-read permission does not establish that memory was read.',
                               'File creation is not proof of encryption; raw IP or script execution alone is not labeled malicious.',
                               'Candidate windows include first concerning events and minute endpoints; rows are correlated.',
                               'Process paths anonymized; no commands, binaries or network connections executed.'])
    (output / 'provenance.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--service', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    build(args.source.resolve(strict=True), args.service.resolve(strict=True), args.output.resolve())
