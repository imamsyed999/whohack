"""Measure an unqualified candidate through whohack's existing native CPU sidecar.

This runs a bounded, separate process. It does not alter the live configuration,
calibration, checkpoint, enforcement or operating thresholds.
"""
import argparse
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import threading
import time

from dataset import LABELS, read_jsonl, sha256, validate
from evaluate import percentile


def tree_rss(process):
    # Windows venv python.exe can be a small launcher whose child runs the model.
    # Count the whole owned tree rather than reporting the launcher's ~4 MB RSS.
    return sum(p.memory_info().rss for p in [process, *process.children(recursive=True)])


def stop_owned_tree(child):
    import psutil
    try:
        root = psutil.Process(child.pid)
        owned = [*reversed(root.children(recursive=True)), root]
        for process in owned:
            try:
                process.terminate()
            except psutil.NoSuchProcess:
                pass
    except psutil.NoSuchProcess:
        pass


def check(args):
    import psutil
    rows = [r for r in validate(read_jsonl(args.dataset)) if r['split'] == 'test']
    gpu = {r['id']: r for r in read_jsonl(args.gpu_predictions)}
    # One case per recipe first, then fill remaining slots. Selection uses only
    # metadata, never whether a prediction happened to be correct.
    selected, families = [], set()
    for row in rows:
        if row['family'] not in families:
            selected.append(row)
            families.add(row['family'])
    selected += [r for r in rows if r['id'] not in {s['id'] for s in selected}]
    selected = selected[:args.max_cases]
    if not 1 <= args.max_cases <= 32 or not selected:
        raise ValueError('CPU compatibility check requires 1-32 cases')
    model = args.model.resolve(strict=True)
    before = {str(p.relative_to(model)): sha256(p) for p in model.rglob('*') if p.is_file()}
    args.output.mkdir(parents=True, exist_ok=False)
    sidecar = Path(__file__).resolve().parent / 'research/decision_sidecar.py'
    command = [str(args.cpu_python.resolve(strict=True)), '-u', str(sidecar), '--backend', 'laya',
               '--model-dir', str(model), '--device', 'cpu', '--threads', '4', '--dtype', 'float32',
               '--calibration', str(model / 'calibration.json')]
    messages = queue.Queue()
    child = None
    stopped = threading.Event()
    peak = [0]
    report = dict(qualified=False, status='starting', cases=len(selected), full_release_evaluation=False,
                  model_weights_sha256=before['model.safetensors'],
                  calibration_sha256=before['calibration.json'],
                  sidecar_sha256=sha256(sidecar), device='cpu', threads=4, results=[])
    try:
        with (args.output / 'sidecar-stderr.log').open('w', encoding='utf-8') as errors:
            child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=errors, text=True, encoding='utf-8', bufsize=1,
                                     creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
            def reader():
                for line in child.stdout:
                    messages.put(line)
                messages.put(None)
            def sample_memory():
                process = psutil.Process(child.pid)
                while not stopped.wait(.05):
                    try:
                        peak[0] = max(peak[0], tree_rss(process))
                        if peak[0] > 8_000_000_000:
                            stop_owned_tree(child)
                            messages.put(None)
                            return
                    except psutil.NoSuchProcess:
                        return
            threading.Thread(target=reader, daemon=True).start()
            monitor = threading.Thread(target=sample_memory, daemon=True)
            monitor.start()
            def receive(timeout=60):
                line = messages.get(timeout=timeout)
                if line is None:
                    raise RuntimeError('sidecar exited before its expected response; see stderr log')
                return json.loads(line)
            def send(message):
                child.stdin.write(json.dumps(message) + '\n')
                child.stdin.flush()
            ready = receive(120)
            if ready.get('type') != 'ready' or ready.get('backend') != 'laya' or ready.get('device') != 'cpu':
                raise ValueError('invalid sidecar handshake')
            report['ready'] = ready
            for row in selected:
                send(dict(op='decide', id=row['id'], state=row['state'], questions=row['questions'], max_state_tokens=768))
                response = receive()
                if response.get('id') != row['id'] or response.get('ok') is not True:
                    raise ValueError('candidate request failed: ' + json.dumps(response))
                if response['usage']['truncated']:
                    raise ValueError('candidate evidence was truncated')
                answers = {a['id']: a for a in response['answers']}
                if set(answers) != set(LABELS):
                    raise ValueError('sidecar question contract differs')
                delta = 0.
                tops_match = True
                for qid, labels in LABELS.items():
                    answer = answers[qid]
                    if answer['labels'] != labels:
                        raise ValueError('sidecar label order differs')
                    reference = gpu[row['id']]['probabilities'][qid]
                    delta = max(delta, max(abs(p - reference[label]) for label, p in zip(labels, answer['probs'])))
                    tops_match &= labels[max(range(len(labels)), key=lambda i: answer['probs'][i])] == max(labels, key=lambda l: reference[l])
                report['results'].append(dict(id=row['id'], family=row['family'], latency_ms=response['latency_ms'],
                                               max_probability_delta=delta, top_answers_match=bool(tops_match), usage=response['usage']))
            send(dict(op='shutdown', id='finish'))
            if receive().get('ok') is not True:
                raise ValueError('sidecar shutdown failed')
            child.wait(timeout=10)
            if child.returncode != 0:
                raise ValueError('sidecar exited with an error')
            report['status'] = 'completed'
    except Exception as exc:
        report.update(status='failed', error=type(exc).__name__ + ': ' + str(exc))
        raise
    finally:
        stopped.set()
        if child and child.poll() is None:
            stop_owned_tree(child)
            child.wait(timeout=10)
        report['peak_rss_mb'] = peak[0] / 1_000_000
        after = {str(p.relative_to(model)): sha256(p) for p in model.rglob('*') if p.is_file()}
        report['checkpoint_unchanged'] = before == after
        latencies = [r['latency_ms'] for r in report['results']]
        report.update(cpu_p50_ms=percentile(latencies, .5), cpu_p95_ms=percentile(latencies, .95))
        if latencies:
            report['max_probability_delta'] = max(r['max_probability_delta'] for r in report['results'])
            report['all_top_answers_match'] = all(r['top_answers_match'] for r in report['results'])
        (args.output / 'report.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        print(json.dumps(report, indent=2), flush=True)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('dataset', type=Path)
    p.add_argument('--gpu-predictions', type=Path, required=True)
    p.add_argument('--model', type=Path, required=True)
    p.add_argument('--cpu-python', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--max-cases', type=int, default=16)
    check(p.parse_args())
