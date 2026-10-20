"""Bounded full-encoder Laya training, with independent validation and calibration.

Uses a separately installed, pinned Laya 0.4.11 overlay. This never installs a
candidate in whohack or enables model-driven enforcement.
"""
import argparse
from dataclasses import asdict
import gc
import importlib.metadata
import json
import math
import os
from pathlib import Path
import sys
import time

from calibrate import fit, softmax
from dataset import CONTRACT, LABELS, read_jsonl, sha256, validate, write_jsonl
from evaluate import evaluate, f32, top_label
from finetune import laya_rows
from training_budget import Budget, ResourceGuard

PINNED_LAYA = '0.4.11'


def partitions(rows):
    validate(rows)
    groups = {'train': [], 'select': [], 'calibrate': [], 'test': []}
    family_roles = {}
    state_roles = {}
    app_roles = {}
    for row in rows:
        role = row.get('validation_role') if row['split'] == 'val' else row['split']
        if role not in groups:
            raise ValueError('validation rows need separate select/calibrate roles')
        for index, identity in ((family_roles, row['family']), (app_roles, row['app_sha256'].lower()),
                                (state_roles, row['state'])):
            if identity in index and index[identity] != role:
                raise ValueError('leakage between selection and calibration partitions')
            index[identity] = role
        groups[role].append(row)
    if any(len(values) < 10 for values in groups.values()):
        raise ValueError('each of train/select/calibrate/test needs at least ten cases')
    return groups


def canonical_logits(records, rows):
    if len(records) != len(rows) * len(LABELS):
        raise ValueError('prediction count differs from contract')
    predictions = []
    for index, row in enumerate(rows):
        logits = {}
        for offset, (qid, labels) in enumerate(LABELS.items()):
            _, values, _, count = records[index * len(LABELS) + offset]
            if count != len(labels):
                raise ValueError('prediction option count differs')
            values = list(map(float, values))
            # Official noul rendering is [false, true]; whohack is [yes, no].
            if qid == 'matches_purpose':
                values.reverse()
            if not all(math.isfinite(value) for value in values):
                raise ValueError('nonfinite logits')
            logits[qid] = dict(zip(labels, values))
        predictions.append(dict(id=row['id'], logits=logits))
    return predictions


def add_probabilities(predictions, temperatures):
    for p in predictions:
        p['probabilities'] = {
            q: dict(zip(labels, softmax([p['logits'][q][label] for label in labels], temperatures.get(q, 1))))
            for q, labels in LABELS.items()
        }
    return predictions


def validation_metrics(rows, predictions):
    add_probabilities(predictions, {})
    loss, correct, totals = 0., {q: 0 for q in LABELS}, {}
    blocks = {'benign': [], 'malicious': []}
    for row, prediction in zip(rows, predictions):
        if row['id'] != prediction['id']:
            raise ValueError('prediction order mismatch')
        p = prediction['probabilities']
        for q, labels in LABELS.items():
            best = top_label(labels, p[q])
            correct[q] += best == row['labels'][q]
            totals.setdefault(q, {}).setdefault(best, 0)
            totals[q][best] += 1
            loss -= math.log(max(p[q][row['labels'][q]], 1e-15))
        verdict = row['labels']['verdict']
        if verdict in blocks:
            action = top_label(LABELS['action'], p['action'])
            blocks[verdict].append(f32(p['verdict']['malicious']) >= f32(.5) or f32(p['verdict']['suspicious']) >= f32(.6)
                                   or action in ('block_network', 'kill_and_quarantine'))
    return dict(loss=loss / (len(rows) * len(LABELS)),
                accuracy={q: value / len(rows) for q, value in correct.items()},
                predicted_labels=totals,
                benign_fpr=sum(blocks['benign']) / len(blocks['benign']) if blocks['benign'] else None,
                malicious_recall=sum(blocks['malicious']) / len(blocks['malicious']) if blocks['malicious'] else None)


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + '\n', encoding='utf-8')


def base_provenance(base):
    acquisition = base / 'acquisition.json'
    if acquisition.is_file():
        return dict(kind='upstream_acquisition', acquisition=json.loads(acquisition.read_text(encoding='utf-8')),
                    acquisition_sha256=sha256(acquisition))
    previous = base.parent / 'training-report.json'
    report = json.loads(previous.read_text(encoding='utf-8'))
    kind = 'continued_finetune'
    if report.get('status') == 'failed' and report.get('error', '').startswith('ResourceStop:'):
        finalized = base.parent / 'evaluation-finalized/finalization-report.json'
        recovery = json.loads(finalized.read_text(encoding='utf-8'))
        if (recovery.get('status') != 'completed' or recovery.get('gradient_updates') != 0
                or recovery.get('training_report_sha256') != sha256(previous)
                or recovery.get('dataset_sha256') != report['dataset_sha256']):
            raise ValueError('finalized checkpoint is not tied to the stopped parent report')
        previous, report = finalized, recovery
        kind = 'continued_selected_checkpoint_after_resource_stop'
    identity = report.get('candidate', {})
    if report.get('status') != 'completed' or identity.get('weights_sha256') != sha256(base / 'model.safetensors'):
        raise ValueError('continued-training base does not match its completed parent report')
    if identity.get('calibration_sha256') != sha256(base / 'calibration.json'):
        raise ValueError('continued-training parent calibration changed')
    return dict(kind=kind, parent_report_sha256=sha256(previous),
                parent_dataset_sha256=report['dataset_sha256'], parent_candidate=identity,
                upstream=report['base_acquisition'])


class EarlyStop(Exception):
    pass


def train(args):
    if args.output.exists():
        raise ValueError('use a new run directory; existing checkpoints are preserved')
    if not 1 <= args.epochs <= 32 or not 1 <= args.patience <= 8 or not 1 <= args.micro_batch <= 8:
        raise ValueError('bounded epochs, patience and micro-batch required')
    rows = validate(read_jsonl(args.dataset))
    groups = partitions(rows)
    synthetic = any(r['synthetic'] for r in rows)
    if synthetic and not args.allow_synthetic:
        raise ValueError('synthetic training requires --allow-synthetic and cannot qualify')
    base, overlay = args.base.resolve(strict=True), args.laya_overlay.resolve(strict=True)
    # Local paths only. No package or model download occurs during training.
    os.environ.update(HF_HUB_OFFLINE='1', TRANSFORMERS_OFFLINE='1', USE_TF='0',
                      TOKENIZERS_PARALLELISM='false', OMP_NUM_THREADS='4')
    sys.path.insert(0, str(overlay))
    import laya
    if not Path(laya.__file__).resolve().is_relative_to(overlay):
        raise ValueError('Laya did not load from the explicit training overlay')
    if importlib.metadata.version('laya') != PINNED_LAYA:
        raise ValueError('training API requires the verified Laya 0.4.11 overlay')
    import psutil
    import torch
    from laya.train import (TrainConfig, calibration_records, items_from_rows, load_checkpoint,
                            save_checkpoint, train_model)
    from laya.calibrate import fit_temperature_map
    from laya.agent import _fix_tokenizer_config
    from safetensors.torch import load_file
    args.output.mkdir(parents=True)
    (args.output / 'training-source.py').write_bytes(Path(__file__).read_bytes())
    (args.output / 'training-budget-source.py').write_bytes(Path(__file__).with_name('training_budget.py').read_bytes())
    budget = Budget(allocator_bytes=args.allocator_gb * 1_000_000_000, max_seconds=args.max_minutes * 60)
    report = dict(qualified=False, status='starting', backend='laya', laya_version=PINNED_LAYA,
                  dataset_sha256=sha256(args.dataset), base_weights_sha256=sha256(base / 'model.safetensors'),
                  trainer_sha256=sha256(Path(__file__)),
                  resource_guard_sha256=sha256(Path(__file__).with_name('training_budget.py')),
                  upstream_trainer_sha256=sha256(overlay / 'laya/train.py'),
                  base_acquisition=base_provenance(base),
                  synthetic=synthetic, reviewed_cases=sum(r.get('review', {}).get('accepted', False) for r in rows),
                  partitions={role: dict(cases=len(group), families=sorted({r['family'] for r in group}))
                              for role, group in groups.items()}, history=[], budget=asdict(budget),
                  evaluation_uses='test once after checkpoint selection; calibration families separate',
                  automatic_response_enabled=False)
    write_json(args.output / 'training-report.json', report)
    guard = ResourceGuard(args.output, budget)
    try:
        guard.start(torch)
        print('Loading local Laya; allocator capped at', budget.allocator_bytes, 'bytes', flush=True)
        model, tok, cfg = load_checkpoint(str(base))
        guard.attach(model)
        report['tokenizer_config_sha256_after_upstream_normalization'] = sha256(base / 'tokenizer/tokenizer_config.json')
        report['parameters'] = sum(p.numel() for p in model.parameters())
        report['trainable_parameters'] = sum(p.numel() for p in model.parameters() if p.requires_grad)
        report['device'] = torch.cuda.get_device_name(0)
        max_len, head_max_len = int(cfg['max_len']), int(cfg['head_max_len'])
        lengths = [len(tok.encode(row['state'], add_special_tokens=False)) for row in rows]
        if max(lengths) + head_max_len + 4 > max_len:
            raise ValueError('state might be truncated by the question head; adjust the data budget explicitly')
        report['max_state_tokens'] = max(lengths)
        items = {}
        for role, group in groups.items():
            items[role], skipped = items_from_rows(tok, laya_rows(group), max_len, head_max_len,
                                                   label_smoothing=.02 if role == 'train' else 0.)
            if skipped or len(items[role]) != len(group) * len(LABELS):
                raise ValueError('training items skipped: ' + str(skipped))
        device = torch.device('cuda:0')
        model.to(device)
        def predict(role):
            records = calibration_records(model, tok, items[role], device, max_len, head_max_len, batch_size=2)
            return records, canonical_logits(records, groups[role])
        _, baseline = predict('select')
        report['baseline_selection'] = validation_metrics(groups['select'], baseline)
        print('Base selection:', json.dumps(report['baseline_selection']), flush=True)
        config = TrainConfig(epochs=args.epochs, micro_batch=args.micro_batch, grad_accum=8,
                             encoder_lr=1e-5, head_lr=5e-5, loss='soft-ce', seed=20261018,
                             freeze_encoder=False, gradient_checkpointing=True, amp=True,
                             shuffle_options=('choice', 'noul'), label_smoothing=.02, log_every=50)
        config.validate()
        report['config'] = asdict(config)
        report['status'] = 'training'
        best, best_epoch, stale = math.inf, None, 0
        checkpoint = args.output / 'checkpoint'
        def epoch_end(epoch, loss):
            nonlocal best, best_epoch, stale
            guard.check()
            if not math.isfinite(loss):
                raise ValueError('training loss is nonfinite')
            _, predictions = predict('select')
            metrics = validation_metrics(groups['select'], predictions)
            improved = metrics['loss'] < best - .002
            if improved:
                best, best_epoch, stale = metrics['loss'], epoch + 1, 0
                # Only this run's one checkpoint is overwritten; no epoch copies.
                save_checkpoint(model, tok, cfg, str(checkpoint))
                # transformers 5 writes TokenizersBackend; normalize before
                # pinning so the existing read-only serving adapter can load it.
                _fix_tokenizer_config(str(checkpoint))
            else:
                stale += 1
            report['history'].append(dict(epoch=epoch + 1, training_loss=loss, selection=metrics,
                                          saved_best=improved, elapsed_seconds=time.monotonic() - guard.started))
            report['best_epoch'] = best_epoch
            write_json(args.output / 'training-report.json', report)
            print('Validation:', json.dumps(report['history'][-1]), flush=True)
            # Upstream calibration_records switches eval on; restore training
            # before the next epoch (including encoder checkpointing behavior).
            model.train()
            if stale >= args.patience:
                raise EarlyStop('validation did not improve for %d epochs' % stale)
        try:
            train_model(model, tok, items['train'], config, device, max_len, head_max_len, on_epoch_end=epoch_end)
            report['stop'] = 'epoch budget completed'
        except EarlyStop as exc:
            report['stop'] = str(exc)
        gc.collect()
        torch.cuda.empty_cache()
        guard.check()
        model.load_state_dict(load_file(str(checkpoint / 'model.safetensors')), strict=True)
        model.eval()
        records, calibration_predictions = predict('calibrate')
        temperatures = fit(groups['calibrate'], calibration_predictions)
        write_json(checkpoint / 'calibration.json', temperatures)
        write_json(checkpoint / 'calibration.provenance.json', dict(
            dataset_sha256=sha256(args.dataset), cases=len(groups['calibrate']),
            families=sorted({r['family'] for r in groups['calibrate']}), split='val', role='calibrate',
            synthetic=synthetic, selection_and_test_excluded=True))
        # Also calibrate the upstream per-type/bucket inference interface. whohack's
        # sidecar uses the explicitly hashed per-question calibration above.
        upstream_calibration = fit_temperature_map(records)
        write_json(checkpoint / 'upstream-calibration.json', upstream_calibration)
        cfg.update(temperature=upstream_calibration['temperature'],
                   temperature_by_options=upstream_calibration['temperature_by_options'],
                   fine_tuned=True, training=dict(epochs_completed=len(report['history']), best_epoch=best_epoch,
                       full_encoder=True, dataset_sha256=sha256(args.dataset), synthetic=synthetic, qualified=False))
        write_json(checkpoint / 'rl_agent_config.json', cfg)
        identity = dict(model='whohack-laya-security-development', revision=sha256(checkpoint / 'model.safetensors')[:16],
                        weights_sha256=sha256(checkpoint / 'model.safetensors'), head_sha256=None,
                        calibration_sha256=sha256(checkpoint / 'calibration.json'),
                        synthetic=synthetic, device='cuda', thresholds=CONTRACT['thresholds'])
        predictions = []
        # Time complete five-question requests; these are explicitly GPU timings.
        for index, row in enumerate(groups['test']):
            torch.cuda.synchronize()
            start = time.perf_counter()
            records = calibration_records(model, tok, items['test'][index * 5:(index + 1) * 5],
                                           device, max_len, head_max_len, batch_size=2)
            torch.cuda.synchronize()
            prediction = canonical_logits(records, [row])[0]
            prediction.update(identity, latency_ms=(time.perf_counter() - start) * 1000,
                              rss_mb=psutil.Process().memory_info().rss / 1_000_000)
            predictions.append(prediction)
        add_probabilities(predictions, temperatures)
        write_jsonl(args.output / 'test-predictions.jsonl', predictions)
        evaluation = evaluate(rows, predictions)
        # Existing evaluator's CPU-named fields are meaningful only for CPU runs.
        evaluation['gpu_p50_ms'] = evaluation.pop('cpu_p50_ms')
        evaluation['gpu_p95_ms'] = evaluation.pop('cpu_p95_ms')
        evaluation.update(cpu_p50_ms=None, cpu_p95_ms=None, device='cuda',
                          dataset_sha256=sha256(args.dataset),
                          predictions_sha256=sha256(args.output / 'test-predictions.jsonl'))
        write_json(args.output / 'evaluation.json', evaluation)
        # Compare the parent only after selection/calibration are finished. The
        # fresh test never selects epochs, thresholds, or a second training run.
        if (base / 'calibration.json').is_file():
            model.load_state_dict(load_file(str(base / 'model.safetensors')), strict=True)
            model.eval()
            _, parent_predictions = predict('test')
            parent_temperatures = json.loads((base / 'calibration.json').read_text(encoding='utf-8'))
            add_probabilities(parent_predictions, parent_temperatures)
            parent_identity = dict(model='previous-laya-candidate', revision=report['base_weights_sha256'][:16],
                                   weights_sha256=report['base_weights_sha256'], head_sha256=None,
                                   calibration_sha256=sha256(base / 'calibration.json'), synthetic=synthetic,
                                   device='cuda', thresholds=CONTRACT['thresholds'])
            for prediction in parent_predictions:
                prediction.update(parent_identity)
            write_jsonl(args.output / 'parent-test-predictions.jsonl', parent_predictions)
            parent_evaluation = evaluate(rows, parent_predictions)
            write_json(args.output / 'parent-evaluation.json', parent_evaluation)
            comparison = dict(cases=len(groups['test']), independent_real_world_test=False,
                              parent=parent_evaluation['per_question'], candidate=evaluation['per_question'],
                              accuracy_delta={q: evaluation['per_question'][q]['accuracy'] - parent_evaluation['per_question'][q]['accuracy'] for q in LABELS},
                              parent_benign_fpr=parent_evaluation['benign_fpr'], candidate_benign_fpr=evaluation['benign_fpr'],
                              parent_malicious_recall=parent_evaluation['malicious_recall'], candidate_malicious_recall=evaluation['malicious_recall'],
                              limitations='Authored recipes share primitives. Public weak labels are training-only. Not a market comparison.')
            write_json(args.output / 'comparison.json', comparison)
            report['comparison'] = comparison
        report.update(status='completed', qualified=False, evaluation=evaluation,
                      candidate=identity, temperatures=temperatures,
                      weights_changed=identity['weights_sha256'] != report['base_weights_sha256'])
        print('Completed; candidate remains UNQUALIFIED:', json.dumps(evaluation), flush=True)
    except BaseException as exc:
        report.update(status='failed', error=type(exc).__name__ + ': ' + str(exc), qualified=False)
        raise
    finally:
        try:
            guard.close(torch)
        except Exception as exc:
            report['cleanup_error'] = type(exc).__name__ + ': ' + str(exc)
            raise
        finally:
            report['elapsed_seconds'] = time.monotonic() - guard.started
            write_json(args.output / 'training-report.json', report)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('dataset', type=Path)
    p.add_argument('--base', type=Path, required=True)
    p.add_argument('--laya-overlay', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--epochs', type=int, default=16)
    p.add_argument('--patience', type=int, default=3)
    p.add_argument('--micro-batch', type=int, default=4)
    p.add_argument('--allocator-gb', type=int, default=16)
    p.add_argument('--max-minutes', type=int, default=90)
    p.add_argument('--allow-synthetic', action='store_true')
    train(p.parse_args())
