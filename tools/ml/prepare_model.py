"""Pin an existing local model installation; never downloads or installs packages."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import tempfile


def model_files(root):
    """Match the service's bounded regular-file contract; prune HF bookkeeping."""
    count, size = 0, 0
    for directory, dirs, names in os.walk(root, followlinks=False):
        directory = Path(directory)
        if len(directory.relative_to(root).parts) > 16:
            raise ValueError('model tree is nested too deeply')
        for name in dirs[:]:
            path = directory / name
            if path.is_symlink(): raise ValueError('model directory must not contain symlinks')
            count += 1
            if name == '.cache': dirs.remove(name)
        for name in sorted(names):
            path = directory / name
            count += 1
            if count > 4096 or path.is_symlink() or not path.is_file():
                raise ValueError('invalid or oversized model file tree')
            if path.suffix.lower() in {'.bin', '.pt', '.pth', '.pkl', '.pickle', '.py'}:
                raise ValueError('use safetensors; model code and pickle files are not permitted')
            length = path.stat().st_size; size += length
            if length > 4 * 1024**3 or size > 8 * 1024**3:
                raise ValueError('model exceeds the service file-size limit')
            yield path
        if count > 4096: raise ValueError('too many model files/directories')


def laya_tokenizer(root, normalize):
    path = root / 'tokenizer/tokenizer_config.json'
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
        raise ValueError('invalid Laya tokenizer configuration')
    data = json.loads(path.read_text(encoding='utf-8'))
    changed = False
    if data.get('tokenizer_class') in (None, 'TokenizersBackend'):
        data['tokenizer_class'] = 'PreTrainedTokenizerFast'
        data.pop('backend', None); data.pop('is_local', None); changed = True
    extra = data.get('extra_special_tokens')
    if isinstance(extra, list):
        data['extra_special_tokens'] = {f'extra_{i}': value for i, value in enumerate(extra)}
        changed = True
    if changed:
        if not normalize:
            raise ValueError('Laya tokenizer needs its compatibility migration; rerun with --normalize-laya-tokenizer before pinning')
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=path.parent, delete=False) as file:
            staged = Path(file.name)
            json.dump(data, file, indent=2); file.write('\n'); file.flush(); os.fsync(file.fileno())
        try:
            os.chmod(staged, path.stat().st_mode & 0o777)
            os.replace(staged, path)
        finally:
            staged.unlink(missing_ok=True)


def digest(path):
    with Path(path).open("rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model-dir", type=Path, required=True)
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--backend", choices=["laya", "opendecider"], required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--dtype", choices=["float32", "bfloat16"])
    parser.add_argument("--calibration", help="pinned filename within model-dir")
    parser.add_argument("--evaluation", help="pinned filename within model-dir")
    parser.add_argument("--normalize-laya-tokenizer", action='store_true', help='explicitly migrate an old Laya tokenizer config before hashing it')
    args = parser.parse_args()
    model_dir, python = args.model_dir.resolve(strict=True), args.python.resolve(strict=True)
    script = Path(__file__).resolve().parents[2] / "ml/research/decision_sidecar.py"
    if args.output.resolve().is_relative_to(model_dir):
        parser.error('write the manifest outside model-dir so it cannot include itself')
    if args.normalize_laya_tokenizer and args.backend != 'laya':
        parser.error('--normalize-laya-tokenizer requires --backend laya')
    files = {}
    try:
        paths = list(model_files(model_dir))
        if args.backend == 'laya': laya_tokenizer(model_dir, args.normalize_laya_tokenizer)
        for path in paths:
            files[path.relative_to(model_dir).as_posix()] = digest(path)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    required = ({"config.json", "tokenizer.json", "model.safetensors", "head.safetensors"} if args.backend == 'opendecider'
                else {"rl_agent_config.json", "encoder/config.json", "tokenizer/tokenizer.json", "tokenizer/tokenizer_config.json", "model.safetensors"})
    if not required <= files.keys():
        parser.error("model is incomplete")
    dtype = args.dtype or ('float32' if args.backend == 'laya' else 'bfloat16')
    if args.backend == 'laya' and dtype != 'float32':
        parser.error("the verified Laya adapter requires float32")
    for name in [args.evaluation, args.calibration]:
        if name and name not in files:
            parser.error("calibration/evaluation must be files inside model-dir")
    manifest = dict(version=1, model_name=args.backend, revision=args.revision, backend=args.backend,
                    python=str(python), script=str(script), script_sha256=digest(script),
                    model_dir=str(model_dir), files=files, dtype=dtype, threads=4,
                    max_state_tokens=768, evaluation=args.evaluation, calibration=args.calibration)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Pinned {len(files)} model files: {args.output}")
    print("Advisory mode; no validated model report supplied." if not args.evaluation else "The service will verify the quality report before enabling model response.")


if __name__ == "__main__":
    main()
