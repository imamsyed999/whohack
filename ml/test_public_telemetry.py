import json
import copy
import hashlib
from pathlib import Path
import tempfile
import unittest

from dataset import sha256
from acquire_behavior_telemetry import validate_catalog, verified_text
from expanded_scenarios import EXTRA
from import_sysmon import observed_kind, parse_line, persistence, provisional_labels, validate_acquisition
from security_scenarios import RECIPES
from train_laya import base_provenance


class EvidenceTests(unittest.TestCase):
    def test_query_only_lsass_handle_is_not_credential_read(self):
        data = dict(GrantedAccess='0x1000', TargetImage=r'C:\Windows\System32\lsass.exe')
        self.assertIsNone(observed_kind(10, data, {}))
        data['GrantedAccess'] = '0x1010'
        self.assertEqual(observed_kind(10, data, {})['class'], 'lsass')

    def test_hostname_is_not_a_preceding_dns_answer(self):
        data = dict(_ts=100_000, DestinationIp='203.0.113.7', DestinationPort='443',
                    Protocol='tcp', DestinationHostname='site.test')
        self.assertFalse(observed_kind(3, data, {})['dns_before'])
        self.assertTrue(observed_kind(3, data, {'203.0.113.7': (99_000, 'site.test')})['dns_before'])
        self.assertFalse(observed_kind(3, data, {'203.0.113.7': (101_000, 'site.test')})['dns_before'])

    def test_delete_does_not_become_a_file_write(self):
        self.assertIsNone(observed_kind(23, dict(TargetFilename='C:/a.txt'), {}))
        self.assertIsNone(observed_kind(26, dict(TargetFilename='C:/a.txt'), {}))

    def test_persistence_is_precise_not_any_registry_change(self):
        self.assertEqual(persistence(r'HKCU\Software\Microsoft\Windows\CurrentVersion\Run\app'), 'run_key')
        self.assertIsNone(persistence(r'HKCU\Software\Microsoft\Windows\CurrentVersion\RunMRU\app'))
        self.assertIsNone(observed_kind(12, dict(TargetObject=r'HKCU\Software\Microsoft\Windows\CurrentVersion\Run\app'), {}))

    def test_absence_of_signals_stays_unlabeled(self):
        self.assertIsNone(provisional_labels('FILES sensitive=none\nPERSIST none\nRULES none'))
        self.assertEqual(provisional_labels('PERSIST persistence:run_key')['action'], 'ask_user')
        self.assertIsNone(provisional_labels('APP name=injection-debugger.exe\nPERSIST none\nRULES none'))

    def test_observed_remote_thread_is_conservative_not_an_aggressive_action(self):
        labels = provisional_labels('UNEXPECTED injection:remote_thread(x1)\nPERSIST none')
        self.assertEqual(labels['verdict'], 'suspicious')
        self.assertEqual(labels['action'], 'ask_user')

    def test_public_catalog_requires_bounded_distinct_telemetry(self):
        catalog = json.loads((Path(__file__).parent / 'fixtures/public-telemetry-v2-catalog.json').read_text())
        validate_catalog(catalog)
        for path in ('datasets/malware/../sample/sysmon.log', 'datasets/malware/family/payload.exe',
                     'datasets/attack_techniques/T1003/sysmon\\escape.log'):
            invalid = copy.deepcopy(catalog)
            invalid['files'][0]['path'] = path
            with self.assertRaisesRegex(ValueError, 'telemetry path'):
                validate_catalog(invalid)
        invalid = copy.deepcopy(catalog)
        invalid['files'][0]['bytes'] = 30_000_001
        with self.assertRaisesRegex(ValueError, 'byte budget'):
            validate_catalog(invalid)
        invalid = copy.deepcopy(catalog)
        invalid['files'].append(invalid['files'][0])
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            validate_catalog(invalid)
        invalid = copy.deepcopy(catalog)
        invalid['files'][1]['family'] = invalid['files'][0]['family'].upper()
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            validate_catalog(invalid)

    def test_import_manifest_rejects_unsafe_and_colliding_namespaces(self):
        entry = dict(file='source.log', family='source', source_path='datasets/malware/source/sysmon.log',
                     bytes=10, sha256='a' * 64)
        acquisition = dict(repository='splunk/attack_data', revision='b' * 40, license='Apache-2.0', files=[entry])
        validate_acquisition(acquisition)
        for field, value in (('file', '../source.log'), ('family', '../source'), ('family', 'CON'),
                             ('file', 'NUL.log'),
                             ('source_path', 'datasets/malware/../source/sysmon.log')):
            invalid = copy.deepcopy(acquisition)
            invalid['files'][0][field] = value
            with self.assertRaisesRegex(ValueError, 'unsafe'):
                validate_acquisition(invalid)
        invalid = copy.deepcopy(acquisition)
        second = dict(entry, family='SOURCE', file='other.log', source_path='datasets/malware/other/sysmon.log')
        invalid['files'].append(second)
        with self.assertRaisesRegex(ValueError, 'namespace'):
            validate_acquisition(invalid)

    def test_cached_downloads_are_revalidated_as_text(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'sysmon.log'
            for payload in (b'MZnot-a-log', b'log\x00binary', b'\xff\xfe'):
                path.write_bytes(payload)
                entry = dict(bytes=len(payload), sha256=hashlib.sha256(payload).hexdigest())
                with self.assertRaises((ValueError, UnicodeError)):
                    verified_text(path, entry)
            path.write_bytes(b'valid text')
            with self.assertRaisesRegex(ValueError, 'pinned'):
                verified_text(path, dict(bytes=10, sha256='0' * 64))

    def test_entity_declarations_are_rejected(self):
        with self.assertRaises(ValueError):
            parse_line('<!DOCTYPE foo [<!ENTITY x "x">]><Event/>')

    def test_fresh_recipes_exclude_old_recipe_strings(self):
        self.assertFalse(set(r[2] for r in EXTRA) & set(r[2] for r in RECIPES))
        self.assertEqual(len(EXTRA), len({r[0] for r in EXTRA}))
        self.assertEqual(len(EXTRA), len({r[2] for r in EXTRA}))
        self.assertEqual({r[1] for r in EXTRA}, {'train', 'select', 'calibrate', 'test'})

    def test_continued_training_verifies_parent_identity(self):
        with tempfile.TemporaryDirectory() as root:
            base = Path(root) / 'checkpoint'
            base.mkdir()
            (base / 'model.safetensors').write_bytes(b'fake weights for provenance test')
            (base / 'calibration.json').write_text('{}')
            report = dict(status='completed', candidate=dict(weights_sha256=sha256(base / 'model.safetensors'),
                          calibration_sha256=sha256(base / 'calibration.json')), dataset_sha256='parent', base_acquisition={})
            (base.parent / 'training-report.json').write_text(json.dumps(report))
            self.assertEqual(base_provenance(base)['kind'], 'continued_finetune')
            (base / 'model.safetensors').write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'parent report'):
                base_provenance(base)

    def test_finalized_resource_stop_requires_original_report_digest(self):
        with tempfile.TemporaryDirectory() as root:
            base = Path(root) / 'checkpoint'
            base.mkdir()
            (base / 'model.safetensors').write_bytes(b'selected checkpoint')
            (base / 'calibration.json').write_text('{}')
            parent = base.parent / 'training-report.json'
            parent.write_text(json.dumps(dict(status='failed', error='ResourceStop: stale', dataset_sha256='data')))
            recovered = base.parent / 'evaluation-finalized/finalization-report.json'
            recovered.parent.mkdir()
            recovered.write_text(json.dumps(dict(status='completed', gradient_updates=0,
                training_report_sha256=sha256(parent), dataset_sha256='data', base_acquisition={},
                candidate=dict(weights_sha256=sha256(base / 'model.safetensors'),
                               calibration_sha256=sha256(base / 'calibration.json')))))
            self.assertEqual(base_provenance(base)['kind'], 'continued_selected_checkpoint_after_resource_stop')
            parent.write_text(parent.read_text() + '\n')
            with self.assertRaisesRegex(ValueError, 'stopped parent report'):
                base_provenance(base)


if __name__ == '__main__':
    unittest.main()
