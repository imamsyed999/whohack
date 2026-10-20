"""Calibrate/evaluate a saved best checkpoint after a guarded training stop.

Never resumes gradients, invents completed epochs, or enables live enforcement.
Preserves the failed/stopped training report and compares with the original parent.
"""
import argparse
import importlib.metadata
import json
import os
from pathlib import Path
import sys
import time

from calibrate import fit
from dataset import CONTRACT, LABELS, read_jsonl, sha256, write_jsonl
from evaluate import evaluate
from finetune import laya_rows
from train_laya import PINNED_LAYA, add_probabilities, base_provenance, canonical_logits, partitions, write_json
from training_budget import Budget, ResourceGuard


def finalize(args):
    run = args.run.resolve(strict=True)
    checkpoint = run / 'checkpoint'
    training = json.loads((run / 'training-report.json').read_text(encoding='utf-8'))
    if training.get('status') != 'failed' or not training.get('error', '').startswith('ResourceStop:'):
        raise ValueError('this recovery is restricted to an explicit resource stop')
    if not any(r['epoch'] == training.get('best_epoch') and r['saved_best'] for r in training.get('history', [])):
        raise ValueError('no completed selected checkpoint exists')
    if sha256(args.dataset) != training['dataset_sha256']:
        raise ValueError('dataset differs from stopped training')
    if sha256(args.parent / 'model.safetensors') != training['base_weights_sha256']:
        raise ValueError('comparison parent differs from original training base')
    base_provenance(args.parent.resolve(strict=True))
    rows = read_jsonl(args.dataset)
    groups = partitions(rows)
    if args.output.exists():
        raise ValueError('preserve earlier evaluations; use a new output directory')
    args.output.mkdir(parents=True)
    for source in [Path(__file__), Path(__file__).with_name('training_budget.py')]:
        (args.output / source.name).write_bytes(source.read_bytes())
    os.environ.update(HF_HUB_OFFLINE='1', TRANSFORMERS_OFFLINE='1', USE_TF='0',
                      TOKENIZERS_PARALLELISM='false', OMP_NUM_THREADS='4')
    overlay = args.laya_overlay.resolve(strict=True)
    sys.path.insert(0, str(overlay))
    import laya
    if not Path(laya.__file__).resolve().is_relative_to(overlay) or importlib.metadata.version('laya') != PINNED_LAYA:
        raise ValueError('unexpected training API')
    import psutil
    import torch
    from laya.train import calibration_records, items_from_rows, load_checkpoint
    from safetensors.torch import load_file
    guard = ResourceGuard(args.output, Budget(max_seconds=1200))
    report = dict(status='starting', qualified=False, gradient_updates=0,
                  training_stopped=True, training_stop_reason=training['error'],
                  completed_epochs=len(training['history']), best_epoch=training['best_epoch'],
                  training_report_sha256=sha256(run / 'training-report.json'),
                  dataset_sha256=training['dataset_sha256'], base_acquisition=training['base_acquisition'],
                  synthetic=any(r['synthetic'] for r in rows), automatic_response_enabled=False)
    try:
        guard.start(torch)
        model, tokenizer, cfg = load_checkpoint(str(checkpoint))
        guard.attach(model)
        device = torch.device('cuda:0')
        model.to(device).eval()
        max_len, head_len = int(cfg['max_len']), int(cfg['head_max_len'])
        def predict(group, stem, identity):
            predictions = []
            for index, row in enumerate(group):
                guard.check()
                items, skipped = items_from_rows(tokenizer, laya_rows([row]), max_len, head_len, label_smoothing=0.)
                if skipped or len(items) != len(LABELS):
                    raise ValueError('evaluation item mismatch')
                torch.cuda.synchronize()
                start = time.perf_counter()
                records = calibration_records(model, tokenizer, items, device, max_len, head_len, batch_size=2)
                torch.cuda.synchronize()
                p = canonical_logits(records, [row])[0]
                p.update(identity, latency_ms=(time.perf_counter() - start) * 1000,
                         rss_mb=psutil.Process().memory_info().rss / 1_000_000)
                predictions.append(p)
                # Inference is segmented with idle time on this desktop. Never
                # enqueue another request when monitoring is stale.
                time.sleep(.1)
                if (index + 1) % 50 == 0:
                    print(stem, index + 1, '/', len(group), flush=True)
            return predictions
        weights = sha256(checkpoint / 'model.safetensors')
        calibrated = predict(groups['calibrate'], 'calibration', {})
        temperatures = fit(groups['calibrate'], calibrated)
        write_json(checkpoint / 'calibration.json', temperatures)
        write_json(checkpoint / 'calibration.provenance.json', dict(
            dataset_sha256=training['dataset_sha256'], cases=len(groups['calibrate']),
            families=sorted({r['family'] for r in groups['calibrate']}), split='val', role='calibrate',
            selection_and_test_excluded=True, synthetic=report['synthetic']))
        identity = dict(model='whohack-laya-expanded', revision=weights[:16], weights_sha256=weights,
                        head_sha256=None, calibration_sha256=sha256(checkpoint / 'calibration.json'),
                        synthetic=report['synthetic'], device='cuda', thresholds=CONTRACT['thresholds'])
        candidate = predict(groups['test'], 'fresh candidate test', identity)
        add_probabilities(candidate, temperatures)
        write_jsonl(args.output / 'test-predictions.jsonl', candidate)
        result = evaluate(rows, candidate)
        result['gpu_p50_ms'] = result.pop('cpu_p50_ms')
        result['gpu_p95_ms'] = result.pop('cpu_p95_ms')
        result.update(cpu_p50_ms=None, cpu_p95_ms=None, device='cuda',
                      dataset_sha256=training['dataset_sha256'],
                      predictions_sha256=sha256(args.output / 'test-predictions.jsonl'))
        write_json(args.output / 'evaluation.json', result)
        model.load_state_dict(load_file(str(args.parent / 'model.safetensors')), strict=True)
        model.eval()
        parent_identity = dict(identity, model='previous-laya-candidate',
                               revision=training['base_weights_sha256'][:16], weights_sha256=training['base_weights_sha256'],
                               calibration_sha256=sha256(args.parent / 'calibration.json'))
        parent = predict(groups['test'], 'fresh parent test', parent_identity)
        add_probabilities(parent, json.loads((args.parent / 'calibration.json').read_text()))
        write_jsonl(args.output / 'parent-test-predictions.jsonl', parent)
        parent_result = evaluate(rows, parent)
        parent_result['gpu_p50_ms'] = parent_result.pop('cpu_p50_ms')
        parent_result['gpu_p95_ms'] = parent_result.pop('cpu_p95_ms')
        parent_result.update(cpu_p50_ms=None, cpu_p95_ms=None, device='cuda')
        write_json(args.output / 'parent-evaluation.json', parent_result)
        comparison = dict(cases=len(groups['test']), independent_real_world_test=False,
                          parent=parent_result['per_question'], candidate=result['per_question'],
                          accuracy_delta={q: result['per_question'][q]['accuracy'] - parent_result['per_question'][q]['accuracy'] for q in LABELS},
                          parent_benign_fpr=parent_result['benign_fpr'], candidate_benign_fpr=result['benign_fpr'],
                          parent_malicious_recall=parent_result['malicious_recall'], candidate_malicious_recall=result['malicious_recall'],
                          limitations='Authored cases with overlapping primitives, not independent real-world malware testing.')
        write_json(args.output / 'comparison.json', comparison)
        if sha256(checkpoint / 'model.safetensors') != weights:
            raise ValueError('evaluation changed checkpoint weights')
        cfg.update(fine_tuned=True, training=dict(full_encoder=True, interrupted=True,
            completed_epochs=len(training['history']), best_epoch=training['best_epoch'],
            dataset_sha256=training['dataset_sha256'], synthetic=report['synthetic'], qualified=False))
        write_json(checkpoint / 'rl_agent_config.json', cfg)
        report.update(status='completed', candidate=identity, evaluation=result, comparison=comparison,
                      weights_changed=weights != training['base_weights_sha256'])
        print(json.dumps(comparison, indent=2), flush=True)
    except BaseException as exc:
        report.update(status='failed', error=type(exc).__name__ + ': ' + str(exc))
        raise
    finally:
        try:
            guard.close(torch)
        except Exception as exc:
            report['cleanup_error'] = type(exc).__name__ + ': ' + str(exc)
            raise
        finally:
            report['elapsed_seconds'] = time.monotonic() - guard.started
            write_json(args.output / 'finalization-report.json', report)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for name in ['run', 'dataset', 'parent', 'laya-overlay', 'output']:
        p.add_argument('--' + name, type=Path, required=True)
    finalize(p.parse_args())
