import copy
import math
import tempfile
import unittest
from pathlib import Path
from dataset import CONTRACT, LABELS, validate, split_family
from evaluate import evaluate
from calibrate import fit, softmax


def rows():
    result = []
    for i in range(40):
        verdict = 'malicious' if i % 2 else 'benign'
        result.append(dict(schema_version=1, id=str(i), state=f'APP name=fixture{i}\nANOMALY 0.5',
            source='synthetic unit test', family=f'family{i}', app_sha256=f'{i:064x}',
            split='val' if i < 20 else 'test', synthetic=True, feature_vector=[0.] * 17,
            questions=copy.deepcopy(CONTRACT['questions']), feature_names=CONTRACT['features'].copy(),
            labels=dict(matches_purpose='yes', verdict=verdict, tactic='none', severity='0', action='ask_user'),
            review={'accepted': False}))
    return result


def predictions(data):
    result = []
    for row in data:
        probs, logits = {}, {}
        for q, labels in LABELS.items():
            gold = str(row['labels'][q]); probs[q] = {l: .9 if l == gold else .1 / (len(labels) - 1) for l in labels}
            logits[q] = {l: math.log(v) for l, v in probs[q].items()}
        result.append(dict(id=row['id'], probabilities=probs, logits=logits, synthetic=True, device='cpu', latency_ms=100., rss_mb=100.))
    return result


class PipelineTests(unittest.TestCase):
    def test_leakage_duplicate_and_review_rejection(self):
        data = rows(); validate(data)
        data[20]['family'] = data[0]['family']
        with self.assertRaisesRegex(ValueError, 'leakage'): validate(data)
        data = rows(); data[20]['app_sha256'] = data[0]['app_sha256']
        with self.assertRaisesRegex(ValueError, 'leakage'): validate(data)
        data = rows(); data[20]['state'] = data[0]['state']
        with self.assertRaisesRegex(ValueError, 'leakage'): validate(data)
        data = rows(); data[0]['review'] = {'accepted': True}
        with self.assertRaisesRegex(ValueError, 'review'): validate(data)
        self.assertEqual(split_family('same-family'), split_family('same-family'))
        data = rows(); data[0]['questions'][0]['text'] = 'Different question'
        with self.assertRaisesRegex(ValueError, 'serving contract'): validate(data)
        data = rows(); data[0]['feature_names'].reverse()
        with self.assertRaisesRegex(ValueError, 'feature order'): validate(data)

    def test_perfect_synthetic_predictions_never_qualify(self):
        data = rows(); report = evaluate(data, predictions(data))
        self.assertEqual(report['malicious_recall'], 1.)
        self.assertEqual(report['benign_fpr'], 0.)
        self.assertFalse(report['passed'])
        self.assertIn('representative non-synthetic data', report['failures'])
        self.assertIsNone(report['alerts_per_week'])
        pred = predictions(data); pred[-1]['probabilities']['verdict']['benign'] = float('nan')
        with self.assertRaisesRegex(ValueError, 'probability'): evaluate(data, pred)

    def test_calibration_never_reads_test_labels_or_logits(self):
        data = rows(); pred = predictions(data); first = fit(data, pred)
        for row in data[20:]: row['labels']['verdict'] = 'suspicious'
        for row in pred[20:]: row['logits']['verdict'] = {'unusable': float('nan')}
        self.assertEqual(first, fit(data, pred))
        self.assertAlmostEqual(sum(softmax([1000., 999.])), 1.)
        with self.assertRaises(ValueError): softmax([1., 2.], 0)

    def test_action_ties_and_threshold_identity_match_runtime(self):
        data = rows(); pred = predictions(data)
        for row in pred:
            row['probabilities']['action'] = {label: .25 for label in LABELS['action']}
        self.assertEqual(evaluate(data, pred)['benign_fpr'], 1.)
        pred[-1]['thresholds'] = {**CONTRACT['thresholds'], 'block_malicious': .4}
        with self.assertRaisesRegex(ValueError, 'operating thresholds'): evaluate(data, pred)

    def test_feedback_export_excludes_paths_notes_and_unreviewed_labels(self):
        import sqlite3
        from export_feedback import export
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'test.db'; c = sqlite3.connect(path)
            c.executescript('CREATE TABLE alerts(id INTEGER,target TEXT);CREATE TABLE feedback(id INTEGER,ts INTEGER,user_action TEXT,alert_id INTEGER,note TEXT);CREATE TABLE decisions(id INTEGER,alert_id INTEGER,state_text TEXT,model_name TEXT,model_revision TEXT);')
            import json
            c.execute('INSERT INTO alerts VALUES(1,?)', (json.dumps({'exe': {'sha256': 'ab'*32, 'path': 'PRIVATE_PATH'}}),))
            c.execute("INSERT INTO feedback VALUES(1,10,'allow',1,'PRIVATE_NOTE')")
            c.execute("INSERT INTO decisions VALUES(1,1,'APP name=safe.exe','test','v1')"); c.commit(); c.close()
            result = list(export(path)); text = json.dumps(result)
            self.assertNotIn('PRIVATE_', text); self.assertIsNone(result[0]['labels'])


if __name__ == '__main__':
    unittest.main()
