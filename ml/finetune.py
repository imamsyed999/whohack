"""Local typed-model fine-tuning; never trains on validation or test families.

OpenDecider uses its published nano encoder/mask-head architecture with supervised
cross entropy. Laya export follows the official JSONL contract; execution routes
through the bounded trainer with an explicit, separate Laya 0.4.11 overlay.
"""
import argparse
import json
import os
import random
import shutil
import sys
from pathlib import Path
from dataset import LABELS, read_jsonl, validate, write_jsonl, sha256


def laya_rows(rows):
    for row in rows:
        questions, expected = {}, {}
        for q in row['questions']:
            kind = 'noul' if q['kind'] == 'yes_no' else q['kind']
            questions[q['id']] = dict(type=kind, instructions=q['text'])
            if kind != 'noul': questions[q['id']]['criteria'] = q['options']
            label = row['labels'][q['id']]
            expected[q['id']] = label == 'yes' if kind == 'noul' else int(label) if kind == 'score' else label
        yield dict(state=row['state'], questions=questions, expected=expected)


def train_nano(rows, base, output, epochs, steps, full_encoder, device):
    import torch
    from opendecider import load
    from safetensors.torch import save_file
    torch.manual_seed(4528); torch.set_num_threads(4)
    model = load(str(base), device=device, dtype='bfloat16').impl
    model.head.float()
    if not full_encoder:
        model.enc.requires_grad_(False)
    optimizer = torch.optim.AdamW([p for p in model.parameters() if p.requires_grad], lr=2.5e-5 if full_encoder else 1e-4)
    trained = 0; losses = []
    rng = random.Random(4528)
    for _ in range(epochs):
        shuffled = list(rows); rng.shuffle(shuffled)
        for row in shuffled:
            built, targets = [], []
            for q in row['questions']:
                labels = LABELS[q['id']]
                ids, truncated = model._build(row['state'], q['text'], dict.fromkeys(labels, ''))
                if truncated: raise ValueError('training input exceeds model budget')
                built.append(ids); targets.append(labels.index(str(row['labels'][q['id']])))
            length = max(map(len, built)); pad = model.tok.pad_token_id
            x = torch.tensor([b + [pad] * (length - len(b)) for b in built], device=device)
            mask = torch.tensor([[1] * len(b) + [0] * (length - len(b)) for b in built], device=device)
            optimizer.zero_grad(set_to_none=True)
            with torch.set_grad_enabled(full_encoder):
                hidden = model.enc(input_ids=x, attention_mask=mask).last_hidden_state
            loss = 0.
            for i, ids in enumerate(built):
                positions = torch.tensor([j for j, token in enumerate(ids) if token == model.mask_id], device=device)
                logits = model.head(hidden[i, positions].float()).squeeze(-1)
                if logits.numel() != len(LABELS[row['questions'][i]['id']]):
                    raise ValueError('special token injection or option-count mismatch')
                loss = loss + torch.nn.functional.cross_entropy(logits.unsqueeze(0), torch.tensor([targets[i]], device=device))
            loss = loss / len(built); loss.backward()
            torch.nn.utils.clip_grad_norm_([p for p in model.parameters() if p.requires_grad], 1.)
            optimizer.step(); trained += 1; losses.append(float(loss.detach()))
            if trained >= steps: break
        if trained >= steps: break
    output.mkdir(parents=True, exist_ok=False)
    for file in base.iterdir():
        if file.is_file() and (file.suffix in {'.json', '.safetensors'} or file.name in {'LICENSE', 'README.md'}):
            shutil.copy2(file, output / file.name)
    if full_encoder:
        model.enc.save_pretrained(output, safe_serialization=True)
    save_file({k: v.detach().cpu().contiguous() for k, v in model.head.state_dict().items()}, output / 'head.safetensors')
    return dict(steps=trained, losses=losses, full_encoder=full_encoder, device=device)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('dataset', type=Path); p.add_argument('--base', type=Path, required=True)
    p.add_argument('--backend', choices=['opendecider', 'laya'], default='opendecider')
    p.add_argument('--laya-overlay', type=Path, help='verified Laya 0.4.11 training overlay; never replaces serving packages')
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--epochs', type=int, default=4); p.add_argument('--max-steps', type=int, default=10000)
    p.add_argument('--full-encoder', action='store_true'); p.add_argument('--device', choices=['cpu', 'cuda'], default='cpu')
    p.add_argument('--allow-synthetic', action='store_true'); p.add_argument('--export-only', action='store_true')
    a = p.parse_args(); rows = validate(read_jsonl(a.dataset)); base = a.base.resolve(strict=True)
    if not base.is_dir() or not 1 <= a.epochs <= 100 or not 1 <= a.max_steps <= 1000000:
        p.error('local model directory and bounded positive training budget required')
    if a.output.exists(): p.error('output already exists; use a new checkpoint directory')
    if any(r['synthetic'] for r in rows) and not a.allow_synthetic:
        p.error('synthetic mechanics tests require --allow-synthetic; these checkpoints remain unqualified')
    training = [r for r in rows if r['split'] == 'train']
    if not training: p.error('no training families')
    os.environ.update(HF_HUB_OFFLINE='1', TRANSFORMERS_OFFLINE='1', USE_TF='0')
    if a.backend == 'laya':
        exports = a.output.with_name(a.output.name + '-data'); exports.mkdir(parents=True, exist_ok=True)
        train = exports / 'train.jsonl'; val = exports / 'val.jsonl'
        write_jsonl(train, laya_rows(training)); write_jsonl(val, laya_rows([r for r in rows if r['split'] == 'val']))
        if a.export_only:
            print(f'Exported official Laya training inputs to {exports}; test families excluded.'); return
        if not a.laya_overlay or a.device != 'cuda' or not a.full_encoder:
            p.error('Laya training requires --laya-overlay, --device cuda and --full-encoder. Prefer ml/train_laya.py for the guarded run; compatible JSONL was exported.')
        from train_laya import train as train_laya
        from types import SimpleNamespace
        train_laya(SimpleNamespace(dataset=a.dataset, base=base, output=a.output,
                                   laya_overlay=a.laya_overlay, epochs=a.epochs, patience=3,
                                   micro_batch=4, allocator_gb=16, max_minutes=90,
                                   allow_synthetic=a.allow_synthetic))
        return
    else:
        if a.export_only: p.error('--export-only is for the Laya data adapter')
        report = train_nano(training, base, a.output, a.epochs, a.max_steps, a.full_encoder, a.device)
    report.update(dataset_sha256=sha256(a.dataset), synthetic=any(r['synthetic'] for r in rows), qualified=False,
                  training_families=sorted({r['family'] for r in training}), base_weights_sha256=sha256(base / 'model.safetensors'))
    (a.output / 'training-report.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(f'Checkpoint saved to {a.output}. Calibrate and evaluate held-out families before use.')


if __name__ == '__main__':
    main()
