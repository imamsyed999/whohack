"""Post-selection error analysis; never tunes thresholds or qualifies a model."""
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import re

from dataset import LABELS, probabilities, read_jsonl, sha256
from evaluate import evaluate, top_label

RESTRICTIVE = {'block_network', 'kill_and_quarantine'}


def audit(rows, predictions, parent_predictions=None):
    test = [row for row in rows if row['split'] == 'test']
    expected_ids = {row['id'] for row in test}

    def checked(values):
        if {p['id'] for p in values} != expected_ids:
            raise ValueError('audit predictions must cover exactly the frozen test set')
        result = evaluate(rows, values)  # Check labels, identities and probabilities.
        return result, {p['id']: p for p in values}

    evaluation, index = checked(predictions)
    parent_evaluation, parent = checked(parent_predictions) if parent_predictions is not None else (None, {})
    if parent_evaluation and parent_evaluation['thresholds'] != evaluation['thresholds']:
        raise ValueError('parent and candidate must use the same frozen operating thresholds')
    counters = Counter()
    groups = defaultdict(lambda: Counter())
    confusions = {q: defaultdict(Counter) for q in LABELS}
    errors = []
    deltas = {q: Counter() for q in LABELS}
    for row in test:
        answers = probabilities(index[row['id']])
        predicted = {q: top_label(options, answers[q]) for q, options in LABELS.items()}
        gold = row['labels']
        category_match = re.search(r'\bcategory=([a-z_]+)\b', row['state'].split('\n', 1)[0])
        category = category_match.group(1) if category_match else 'unknown'
        flags = []
        counters['cases'] += 1
        counters[gold['verdict'] + '_cases'] += 1
        if gold['verdict'] == 'benign' and predicted['action'] in RESTRICTIVE:
            flags.append('benign_restrictive_action')
        if gold['action'] == 'ask_user':
            counters['expected_ask_user_cases'] += 1
            if predicted['action'] in RESTRICTIVE:
                flags.append('uncertain_restrictive_action')
            elif predicted['action'] == 'allow':
                flags.append('uncertain_allowed_without_review')
        if gold['verdict'] == 'malicious' and predicted['action'] not in RESTRICTIVE:
            flags.append('malicious_without_restrictive_action')
        if predicted['action'] == 'kill_and_quarantine' and gold['action'] != 'kill_and_quarantine':
            flags.append('excessive_quarantine_recommendation')
        for flag in flags:
            counters[flag] += 1
        mismatches = []
        for q in LABELS:
            confusions[q][gold[q]][predicted[q]] += 1
            if predicted[q] != gold[q]:
                mismatches.append(q)
            if parent:
                old = top_label(LABELS[q], probabilities(parent[row['id']])[q])
                if old == gold[q] and predicted[q] != gold[q]:
                    deltas[q]['regressions'] += 1
                elif old != gold[q] and predicted[q] == gold[q]:
                    deltas[q]['improvements'] += 1
        for name in ('category:' + category, 'verdict:' + gold['verdict'], 'family:' + row['family']):
            group = groups[name]
            group['cases'] += 1
            for q in LABELS:
                group[q + '_correct'] += int(predicted[q] == gold[q])
            group.update(flags)
        if mismatches:
            errors.append(dict(id=row['id'], family=row['family'], category=category,
                               expected=gold, predicted=predicted, mismatches=mismatches,
                               response_errors=flags))
    return dict(
        schema_version=1, qualified=False, test_only=True,
        weights_sha256=evaluation['weights_sha256'],
        calibration_sha256=evaluation['calibration_sha256'],
        counts=dict(counters),
        confusion={q: {label: dict(counts) for label, counts in matrix.items()}
                   for q, matrix in confusions.items()},
        groups={name: dict(counts) for name, counts in sorted(groups.items())},
        parent_change={q: dict(counts) for q, counts in deltas.items()} if parent else None,
        errors=errors,
        limitations=[
            'Action-label mistakes are separate from the serving blocking-policy threshold.',
            'A restrictive recommendation is not evidence that a live response occurred.',
            'Authored test cases are not malware efficacy, decoder coverage or detection latency.',
            'This report is for diagnosis only; inspected test cases must not be recycled into tuning.',
        ])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('dataset', type=Path)
    parser.add_argument('predictions', type=Path)
    parser.add_argument('--parent-predictions', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = audit(read_jsonl(args.dataset), read_jsonl(args.predictions),
                   read_jsonl(args.parent_predictions) if args.parent_predictions else None)
    report.update(dataset_sha256=sha256(args.dataset), predictions_sha256=sha256(args.predictions),
                  parent_predictions_sha256=sha256(args.parent_predictions) if args.parent_predictions else None)
    with args.output.open('x', encoding='utf-8') as output:
        output.write(json.dumps(report, indent=2, allow_nan=False) + '\n')
    print(json.dumps(report['counts'], indent=2))


if __name__ == '__main__':
    main()
