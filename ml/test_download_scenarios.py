"""Dataset isolation tests; no models, network connections or executed samples."""
from copy import deepcopy
from dataclasses import replace
import unittest

from dataset import CONTRACT, LABELS
from download_scenarios import SCENARIOS, assert_evaluation_excluded, check_recipes, digest, events, merge_rows
from security_scenarios import RECIPES


def row(number, role='train', labels=None):
    return dict(schema_version=1, id=digest('id:' + str(number)), state='unique state ' + str(number),
                family='family:' + str(number), app_sha256=digest('app:' + str(number)),
                source='test authored data', synthetic=True, review={'accepted': False},
                split='val' if role in ('select', 'calibrate') else role,
                validation_role=role if role in ('select', 'calibrate') else None,
                feature_vector=[0.] * 17, feature_names=CONTRACT['features'],
                questions=CONTRACT['questions'], labels=labels or SCENARIOS[0].labels)


def inputs():
    previous = [row(index, labels=scenario.labels)
                for index, scenario in enumerate(s for s in SCENARIOS if s.role == 'train')]
    fresh = [row(1000 + offset * 10 + index, role)
             for offset, role in enumerate(('select', 'calibrate', 'test')) for index in range(10)]
    return previous, fresh


class DownloadScenarioTests(unittest.TestCase):
    def test_fresh_recipes_and_label_coverage(self):
        check_recipes()
        train = [s for s in SCENARIOS if s.role == 'train']
        for question, options in LABELS.items():
            self.assertEqual({s.labels[question] for s in train}, set(options))
        self.assertTrue(any(s.matches_purpose == 'yes' and s.verdict == 'suspicious' for s in train))
        self.assertLess(sum(len(s.categories.split()) for s in SCENARIOS), 2 * len(SCENARIOS))

    def test_prior_recipe_renaming_does_not_evade_exclusion(self):
        prior = RECIPES[0]
        with self.assertRaisesRegex(ValueError, 'previously evaluated'):
            check_recipes([replace(SCENARIOS[0], behavior=prior[2])])
        with self.assertRaisesRegex(ValueError, 'previously evaluated'):
            check_recipes([replace(SCENARIOS[0], behavior='read run_key')])

    def test_variants_cover_signatures_without_changing_labels(self):
        for scenario in SCENARIOS:
            for category in scenario.categories.split():
                first, first_meta = events(scenario, category, 0, 0)
                second, second_meta = events(scenario, category, 1, 1)
                self.assertEqual(first_meta['labels'], second_meta['labels'])
                self.assertNotEqual(first[0]['process']['exe']['sign']['type'],
                                    second[0]['process']['exe']['sign']['type'])
                self.assertNotEqual(first_meta['app_sha256'], second_meta['app_sha256'])

    def test_viewer_has_downloaded_input_and_observed_read(self):
        records, meta = events(SCENARIOS[0], 'media_player', 0, 0)
        process = records[0]['process']
        self.assertEqual(process['exe']['origin']['type'], 'installed')
        content = process['downloaded_inputs'][0]
        self.assertEqual(content['file']['origin']['type'], 'downloaded')
        self.assertTrue(any(r['event']['kind'].get('path') == content['file']['path'] for r in records))
        self.assertEqual(meta['phase'], 'after_download_open')

    def test_game_is_downloaded_executable_with_udp_behavior(self):
        records, meta = events(SCENARIOS[1], 'game', 0, 0)
        self.assertEqual(records[0]['process']['exe']['origin']['type'], 'downloaded')
        self.assertTrue(any(r['event']['kind'].get('proto') == 'udp' for r in records))
        self.assertEqual(meta['labels']['action'], 'allow')
        self.assertEqual(meta['phase'], 'after_download_execute')

    def test_previous_evaluation_exclusion_checks_every_identity(self):
        held = row(9000, 'test')
        for field in ('id', 'family', 'app_sha256', 'state'):
            copied = row(9001)
            copied[field] = held[field].upper() if field == 'app_sha256' else held[field]
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, field):
                assert_evaluation_excluded([copied], [held])

    def test_merge_retains_only_old_training_and_excludes_older_holdouts(self):
        previous, fresh = inputs()
        held = row(9000, 'test')
        result, duplicates = merge_rows(previous + [held], fresh, [])
        self.assertEqual(len(result), len(previous) + len(fresh))
        self.assertNotIn(held['id'], {r['id'] for r in result})
        self.assertEqual(duplicates, 0)
        stolen = deepcopy(fresh)
        stolen[0]['state'] = held['state']
        with self.assertRaisesRegex(ValueError, 'contamination'):
            merge_rows(previous, stolen, [], [[held]])

    def test_public_inputs_must_remain_unreviewed_weak_training(self):
        previous, fresh = inputs()
        public = dict(row(9100), synthetic=False, label_quality='weak_observable_behavior')
        result, _ = merge_rows(previous, fresh, [[public]])
        self.assertIn(public, result)
        changes = [dict(split='test'), dict(validation_role='calibrate'),
                   dict(synthetic=True), dict(label_quality='gold'),
                   dict(review={'accepted': True, 'reviewer': 'x', 'reviewed_at': '2026-10-20'})]
        for change in changes:
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'public inputs'):
                merge_rows(previous, fresh, [[dict(public, **change)]])

    def test_duplicate_rows_are_not_additional_training_evidence(self):
        previous, fresh = inputs()
        public = dict(row(9200), synthetic=False, label_quality='weak_observable_behavior')
        result, count = merge_rows(previous, fresh, [[public], [deepcopy(public)]])
        self.assertEqual(count, 1)
        self.assertEqual(sum(r['id'] == public['id'] for r in result), 1)
        renamed = dict(public, id=digest('renamed'))
        _, count = merge_rows(previous, fresh, [[public, renamed]])
        self.assertEqual(count, 1)

    def test_conflicting_duplicates_and_cross_role_states_fail_closed(self):
        previous, fresh = inputs()
        public = dict(row(9300), synthetic=False, label_quality='weak_observable_behavior')
        conflict = deepcopy(public)
        conflict['labels']['action'] = 'ask_user'
        with self.assertRaisesRegex(ValueError, 'conflicting duplicate'):
            merge_rows(previous, fresh, [[public], [conflict]])
        conflict['id'] = digest('different id')
        with self.assertRaisesRegex(ValueError, 'conflicting labels'):
            merge_rows(previous, fresh, [[public, conflict]])
        leaked = deepcopy(fresh)
        leaked[10]['state'] = leaked[0]['state']
        with self.assertRaisesRegex(ValueError, 'conflicting labels or partitions'):
            merge_rows(previous, leaked, [])

    def test_enriched_public_provenance_can_deduplicate_only_the_same_observation(self):
        previous, fresh = inputs()
        public = dict(row(9400), synthetic=False, label_quality='weak_observable_behavior',
                      source_sha256=digest('source log'), source_event_index=5)
        enriched = dict(public, family='renamed-source-family', source_license='Apache-2.0')
        result, duplicates = merge_rows(previous + [public], fresh, [[enriched]])
        self.assertEqual(duplicates, 1)
        self.assertIn(public, result)
        with self.assertRaisesRegex(ValueError, 'conflicting duplicate'):
            merge_rows(previous + [public], fresh, [[dict(enriched, source_event_index=6)]])


if __name__ == '__main__':
    unittest.main()
