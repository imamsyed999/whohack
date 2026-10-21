import copy
import unittest

from audit_download_decisions import audit
from test_pipeline import predictions, rows


class DownloadAuditTests(unittest.TestCase):
    def test_ambiguous_overreaction_is_not_hidden_by_malicious_recall(self):
        data = rows()
        data[-1]['labels'].update(verdict='suspicious', action='ask_user')
        pred = [p for p in predictions(data) if int(p['id']) >= 20]
        parent = copy.deepcopy(pred)
        pred[-1]['probabilities']['action'] = {
            'allow': .01, 'ask_user': .01, 'block_network': .01, 'kill_and_quarantine': .97}
        result = audit(data, pred, parent)
        self.assertEqual(result['counts']['uncertain_restrictive_action'], 1)
        self.assertEqual(result['counts']['excessive_quarantine_recommendation'], 1)
        self.assertEqual(result['parent_change']['action']['regressions'], 1)
        self.assertNotIn('benign_restrictive_action', result['counts'])
        self.assertFalse(result['qualified'])

    def test_rejects_missing_extra_and_duplicate_test_predictions(self):
        data = rows()
        pred = predictions(data)[20:]
        for invalid in [pred[:-1], pred + predictions(data)[:1], pred + pred[:1]]:
            with self.subTest(size=len(invalid)), self.assertRaises(ValueError):
                audit(data, invalid)

    def test_rejects_comparison_after_threshold_change(self):
        data = rows()
        pred = predictions(data)[20:]
        parent = copy.deepcopy(pred)
        from dataset import CONTRACT
        for p in parent:
            p['thresholds'] = dict(CONTRACT['thresholds'], block_suspicious=.7)
        with self.assertRaisesRegex(ValueError, 'same frozen'):
            audit(data, pred, parent)


if __name__ == '__main__':
    unittest.main()
