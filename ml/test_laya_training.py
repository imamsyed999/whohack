"""Safety and contract tests; no GPU allocation, malware or network activity."""
from dataclasses import replace
import unittest
from unittest.mock import Mock, patch

from dataset import LABELS, validate
from security_scenarios import CATEGORIES, RECIPES, events
from train_laya import canonical_logits, partitions
from training_budget import Budget, NvidiaTelemetry, ResourceGuard, ResourceStop
from check_laya_sidecar import tree_rss


class TrainingBudgetTests(unittest.TestCase):
    def setUp(self):
        self.sample = dict(gpu_used_bytes=9e9, rss_bytes=4e9, available_ram_bytes=80e9,
                           free_disk_bytes=100e9, output_bytes=1e9, elapsed_seconds=10,
                           temperature_c=60)

    def test_decimal_ceiling_and_lower_allocator(self):
        b = Budget()
        self.assertEqual(b.ceiling_bytes, 50_000_000_000)
        self.assertEqual(b.fraction(100_000_000_000), .16)
        self.assertIsNone(b.stop_reason(self.sample))

    def test_rejects_unsafe_or_nonfinite_budgets(self):
        for changes in [dict(ceiling_bytes=51_000_000_000), dict(allocator_bytes=46_000_000_000),
                        dict(max_seconds=8000), dict(allocator_bytes=-1), dict(allocator_bytes=float('nan'))]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                replace(Budget(), **changes).validate()
        with self.assertRaises(ValueError):
            Budget().fraction(16_000_000_000)

    def test_stop_before_ceiling(self):
        self.sample['gpu_used_bytes'] = 45_000_000_000
        self.assertIn('gpu_used_bytes', Budget().stop_reason(self.sample))

    def test_missing_telemetry_fails_closed(self):
        for value in [None, float('inf'), float('nan'), -1]:
            self.sample['gpu_used_bytes'] = value
            self.assertIsNotNone(Budget().stop_reason(self.sample))

    def test_ram_disk_temperature_and_runtime(self):
        for key, value in [('available_ram_bytes', 8e9), ('free_disk_bytes', 1e9),
                           ('output_bytes', 3e9), ('elapsed_seconds', 5400),
                           ('temperature_c', 82), ('rss_bytes', 25e9)]:
            with self.subTest(key=key):
                self.assertIn(key, Budget().stop_reason(dict(self.sample, **{key: value})))

    def test_forward_guard_interrupts_owned_job(self):
        guard = ResourceGuard('.', Budget())
        guard.reason = 'budget reached'
        with self.assertRaises(ResourceStop):
            guard.check(None, None)

    def test_each_forward_yields_and_does_not_ignore_monitor_stop(self):
        guard = ResourceGuard('.', Budget())
        guard.torch = Mock()
        guard.next_yield = float('inf')
        with patch('training_budget.time.sleep') as idle:
            guard.check(Mock(), ())
            guard.check(Mock(), ())
        self.assertEqual(guard.torch.cuda.synchronize.call_count, 2)
        self.assertEqual(idle.call_count, 2)
        def stop_during_idle(_):
            guard.reason = 'GPU telemetry is stale'
        with patch('training_budget.time.sleep', side_effect=stop_during_idle):
            with self.assertRaisesRegex(ResourceStop, 'stale'):
                guard.check(Mock(), ())

    def test_forward_idle_is_bounded(self):
        for value in [0, .01, 1, float('nan'), float('inf'), True]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                ResourceGuard('.', Budget(), forward_idle_seconds=value)

    def test_gpu_stream_rejects_stale_and_exited_samples(self):
        stream = NvidiaTelemetry()
        stream.process = Mock()
        stream.process.poll.return_value = None
        stream.ready.set()
        stream.last = (10, 9_000_000_000, 60)
        with patch('training_budget.time.monotonic', return_value=12):
            self.assertEqual(stream.sample(), (9_000_000_000, 60))
        with patch('training_budget.time.monotonic', return_value=19), self.assertRaisesRegex(ResourceStop, 'stale'):
            stream.sample()
        stream.process.poll.return_value = 1
        with self.assertRaisesRegex(ResourceStop, 'exited'):
            stream.sample()

    def test_gpu_stream_invalid_samples_fail_closed(self):
        stream = NvidiaTelemetry()
        stream.process = Mock()
        stream.process.poll.return_value = None
        stream.ready.set()
        stream.error = 'ValueError'
        with self.assertRaises(ResourceStop):
            stream.sample()

    def test_nvml_source_timestamp_cannot_be_refreshed_by_pipe_delay(self):
        stream = NvidiaTelemetry('nvml')
        with patch('training_budget.time.monotonic', return_value=12):
            stream.accept('10,100,60')
            self.assertEqual(stream.last, (10, 100 * 1024**2, 60))
            for bad in ['10,100,60', '2,100,60', '13,100,60', 'nan,100,60']:
                with self.subTest(bad=bad), self.assertRaises(ValueError):
                    stream.accept(bad)
        with patch('training_budget.time.monotonic', return_value=30), self.assertRaises(ValueError):
            stream.accept('11,100,60')

    def test_watchdog_exits_even_if_reporting_and_worker_cleanup_fail(self):
        guard = ResourceGuard('.', Budget())
        guard.reason = 'GPU telemetry is stale'
        guard.stopped = Mock()
        guard.stopped.wait.side_effect = [False, False]
        guard.gpu = Mock()
        guard.gpu.close.side_effect = OSError('cannot terminate worker')
        with patch.object(guard, 'write_report', side_effect=OSError('disk full')):
            with patch('training_budget.os._exit') as emergency_exit:
                with self.assertRaises(OSError):
                    guard._monitor()
                emergency_exit.assert_called_once_with(75)

    def test_stale_sample_during_cooperative_pause_latches_stop(self):
        guard = ResourceGuard('.', Budget())
        guard.torch, guard.gpu = Mock(), Mock()
        guard.gpu.last = (0, 9_000_000_000, 60)
        guard.gpu.sample.side_effect = ResourceStop('GPU telemetry is stale')
        with patch('training_budget.time.monotonic', return_value=20), patch('training_budget.time.sleep'):
            with self.assertRaises(ResourceStop):
                guard.check()
        self.assertEqual(guard.reason, 'GPU telemetry is stale')
        with self.assertRaises(ResourceStop):
            guard.check()

    def test_shutdown_does_not_close_a_pipe_with_an_active_reader(self):
        stream = NvidiaTelemetry()
        stream.process, stream.thread = Mock(), Mock()
        stream.process.poll.return_value = 0
        stream.thread.is_alive.return_value = True
        stream.close()
        stream.process.stdout.close.assert_not_called()

    def test_cpu_memory_counts_the_venv_launcher_and_model_child(self):
        launcher, model = Mock(), Mock()
        launcher.memory_info.return_value.rss = 4_000_000
        model.memory_info.return_value.rss = 2_000_000_000
        launcher.children.return_value = [model]
        self.assertEqual(tree_rss(launcher), 2_004_000_000)
        launcher.children.assert_called_once_with(recursive=True)


class TrainingDataTests(unittest.TestCase):
    def test_entire_recipes_stay_in_one_partition(self):
        self.assertEqual(len(RECIPES), len({r[0] for r in RECIPES}))
        self.assertEqual(len(RECIPES), len({r[2] for r in RECIPES}))
        self.assertEqual({r[1] for r in RECIPES}, {'train', 'select', 'calibrate', 'test'})

    def test_training_has_every_question_label(self):
        rows = [events(recipe, 'media_player', 0, i)[1] for i, recipe in enumerate(RECIPES) if recipe[1] == 'train']
        for qid, labels in LABELS.items():
            self.assertEqual({r['labels'][qid] for r in rows}, set(labels))

    def test_signed_and_unsigned_both_include_benign_and_malicious(self):
        seen = set()
        for i, recipe in enumerate(RECIPES):
            raw, meta = events(recipe, 'media_player', 0, i)
            seen.add((raw[0]['process']['exe']['sign']['type'], meta['labels']['verdict']))
        for signature in ['valid_trusted', 'unsigned']:
            for verdict in ['benign', 'suspicious', 'malicious']:
                self.assertIn((signature, verdict), seen)

    def test_noul_probabilities_have_serving_order(self):
        records = [(0, [3., -2.], [1, 0], 2)]
        records += [(1, list(range(len(labels))), [], len(labels)) for q, labels in LABELS.items() if q != 'matches_purpose']
        prediction = canonical_logits(records, [dict(id='sample')])[0]
        self.assertEqual(prediction['logits']['matches_purpose'], {'yes': -2., 'no': 3.})
        self.assertEqual(prediction['logits']['verdict'], {'benign': 0., 'suspicious': 1., 'malicious': 2.})

    def test_nonfinite_predictions_rejected(self):
        records = [(0, [float('nan')] * len(labels), [], len(labels)) for labels in LABELS.values()]
        with self.assertRaises(ValueError):
            canonical_logits(records, [dict(id='bad')])

    def test_calibration_family_leakage_is_rejected(self):
        # Normal dataset validation permits the same family within val; the
        # trainer must additionally separate checkpoint selection and calibration.
        rows = [dict(split='val', validation_role=role, family='same', app_sha256=role, state=role)
                for role in ['select', 'calibrate']]
        with patch('train_laya.validate'), self.assertRaisesRegex(ValueError, 'leakage'):
            partitions(rows)

    def test_calibration_app_hash_comparison_is_case_insensitive(self):
        rows = [dict(split='val', validation_role=role, family=role, app_sha256=app, state=role)
                for role, app in [('select', 'abcdef'), ('calibrate', 'ABCDEF')]]
        with patch('train_laya.validate'), self.assertRaisesRegex(ValueError, 'leakage'):
            partitions(rows)


if __name__ == '__main__':
    unittest.main()
