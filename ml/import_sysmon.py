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
from pathlib import Path
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
    elif 'evasion:process_injection' in state or 'injection' in state:
        tactic = 'none'
    else:
        return None
    return dict(matches_purpose='no', verdict='suspicious', tactic=tactic,
                severity='2', action='ask_user')


def build(source, service, output):
    if output.exists():
        raise ValueError('use a new output directory')
    acquisition = json.loads((source / 'acquisition.json').read_text())
    if json.loads(subprocess.check_output([str(service), '--model-contract'], text=True)) != CONTRACT:
        raise ValueError('serving contract mismatch')
    output.mkdir(parents=True)
    rows, counts, selected, total_windows = [], Counter(), Counter(), 0
    for entry in acquisition['files']:
        path = source / entry['file']
        if sha256(path) != entry['sha256']:
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
                continue
            processes[(guid.lower(), normal_path(image))].append((number, data))
        records, ends = [], []
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
            dns, last_bucket, last_index = {}, None, None
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
                    ends.append((last_index, identity, process_digest is not None))
                records.append(dict(event=dict(ts=data['_ts'], pid=pid, kind=kind), process=process))
                last_index, last_bucket = len(records) - 1, bucket
            if last_index is not None:
                ends.append((last_index, identity, process_digest is not None))
        if not records:
            selected[entry['family']] = 0
            continue
        fixture = output / (entry['family'] + '.jsonl')
        write_jsonl(fixture, records)
        run = subprocess.run([str(service), '--replay', str(fixture), '--category', 'other'],
                             capture_output=True, text=True, check=True, timeout=180)
        replay = [json.loads(line) for line in run.stdout.splitlines()]
        if len(replay) != len(records):
            raise ValueError('replay output count mismatch')
        seen = set()
        for index, identity, verified in ends:
            total_windows += 1
            result = replay[index]
            state = result.get('state')
            labels = provisional_labels(state) if state else None
            if not labels or state in seen:
                continue
            seen.add(state)
            # Public traces are weak-label training data ONLY. No accuracy claim
            # uses them as a trusted holdout; shared background binaries cannot
            # accidentally cross from training into a public test partition.
            rows.append(dict(schema_version=1, id=digest(entry['sha256'] + ':' + str(index)),
                             state=state, feature_vector=result['feature_vector'],
                             feature_names=CONTRACT['features'], questions=CONTRACT['questions'],
                             labels=labels, source='Splunk attack_data; provisional evidence labels',
                             family='splunk:' + entry['family'], app_sha256=identity,
                             identity_is_recorded_image_hash=verified,
                             fixture_sha256=sha256(fixture), source_sha256=entry['sha256'],
                             source_revision=acquisition['revision'], source_path=entry['source_path'],
                             source_event_index=index, scorer=result['scorer'], replay_config_sha256=None,
                             split='train', validation_role=None, synthetic=False,
                             label_quality='weak_observable_behavior', review=dict(accepted=False),
                             missing_fields=['signature (unsigned placeholder)', 'download origin',
                                             'network byte counts', 'verified start time when absent']))
            selected[entry['family']] += 1
        print('Imported', entry['family'], selected[entry['family']], 'provisional cases', flush=True)
    validate(rows)
    write_jsonl(output / 'dataset.jsonl', rows)
    report = dict(cases=len(rows), observed_windows=total_windows, families=dict(selected), events=dict(counts),
                  acquisition_sha256=sha256(source / 'acquisition.json'), importer_sha256=sha256(Path(__file__)),
                  service_sha256=sha256(service), dataset_sha256=sha256(output / 'dataset.jsonl'),
                  reviewed_cases=0, license='Apache-2.0', qualified=False,
                  limitations=['All public rows are training-only provisional suspicious labels.',
                               'Other windows remain unlabeled; no clean verdict inferred from missing signals.',
                               'Sysmon source visibility differs from native ETW; import does not add sensors.',
                               'Unknown signatures use the existing unsigned schema placeholder.',
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
