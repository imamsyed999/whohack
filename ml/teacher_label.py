"""Run a pinned local model and save predictions for separate human review.

Does not overwrite gold labels or contact a remote teacher. Run in the existing
CPU research environment to capture RSS using psutil.
"""
import argparse
import json
import os
import queue
import subprocess
import threading
import time
from pathlib import Path
from dataset import CONTRACT, read_jsonl, write_jsonl, validate, sha256, probabilities


class LocalModel:
    def __init__(self, manifest):
        manifest = Path(manifest).resolve()
        self.config = json.loads(manifest.read_text(encoding="utf-8"))
        m = self.config
        def absolute(p):
            return (manifest.parent / p).resolve(strict=True)
        self.directory = absolute(m["model_dir"])
        script, python = absolute(m["script"]), absolute(m["python"])
        if sha256(script) != m["script_sha256"]:
            raise ValueError("sidecar script hash differs from manifest")
        for name, digest in m["files"].items():
            path = (self.directory / name).resolve(strict=True)
            if not path.is_relative_to(self.directory) or sha256(path) != digest:
                raise ValueError(f"model file verification failed: {name}")
        command = [str(python), str(script), "--backend", m["backend"], "--model-dir", str(self.directory),
                   "--device", "cpu", "--dtype", m["dtype"], "--threads", str(m["threads"])]
        if m.get("calibration"):
            name = m["calibration"]
            if name not in m["files"]:
                raise ValueError("calibration is not pinned")
            command += ["--calibration", str(self.directory / name)]
        env = dict(os.environ, HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1", PYTHONUNBUFFERED="1")
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env=env, creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        self.lines = queue.Queue(maxsize=2)
        def read():
            try:
                while line := self.process.stdout.readline(1_048_577):
                    if len(line) > 1_048_576:
                        raise ValueError("oversize model response")
                    self.lines.put_nowait(json.loads(line))
            except (ValueError, queue.Full) as e:
                try: self.lines.put_nowait({"error": {"message": str(e)}})
                except queue.Full: pass
        threading.Thread(target=read, daemon=True).start()
        started = time.monotonic()
        try:
            ready = self.lines.get(timeout=60)
            if ready.get("type") != "ready" or ready.get("protocol") != 1:
                raise ValueError("bad model handshake")
        except BaseException:
            self.close(); raise
        self.load_ms = (time.monotonic() - started) * 1000

    def predict(self, row):
        req = dict(id=row["id"], op="decide", state=row["state"], questions=row["questions"],
                   max_state_tokens=self.config["max_state_tokens"])
        start = time.monotonic()
        self.process.stdin.write((json.dumps(req) + "\n").encode()); self.process.stdin.flush()
        try: response = self.lines.get(timeout=10)
        except queue.Empty:
            self.close(); raise TimeoutError("local model inference exceeded ten seconds") from None
        if response.get("id") != row["id"] or not response.get("ok") or response.get("usage", {}).get("truncated"):
            raise ValueError(f"model refused case: {response.get('error')}")
        result = dict(id=row["id"], model=self.config["model_name"], revision=self.config["revision"],
            weights_sha256=self.config['files'].get('model.safetensors'), head_sha256=self.config['files'].get('head.safetensors'),
            calibration_sha256=self.config['files'].get(self.config.get('calibration')),
            thresholds={**CONTRACT['thresholds'], **self.config.get('thresholds', {})},
            synthetic=row["synthetic"], device="cpu", load_ms=self.load_ms,
            latency_ms=(time.monotonic() - start) * 1000, rss_mb=None,
            probabilities={a['id']: dict(zip(a['labels'], a['probs'])) for a in response['answers']},
            logits={a['id']: dict(zip(a['labels'], a['logits'])) for a in response['answers']}, usage=response['usage'])
        probabilities(result)
        try:
            import psutil
            parent = psutil.Process(self.process.pid)
            # Windows virtualenv python.exe is a tiny redirector; the model is
            # in its child. Count the entire owned tree, not just the redirector.
            infos = [p.memory_info() for p in [parent, *parent.children(recursive=True)]]
            result['rss_mb'] = sum(max(i.rss, getattr(i, 'peak_wset', 0)) for i in infos) / 1_000_000
        except ImportError:
            pass  # missing measurements make the release gate fail
        result['proposed_labels'] = {q: max(p, key=p.get) for q, p in result['probabilities'].items()}
        return result

    def close(self):
        if self.process.poll() is None:
            try:
                import psutil
                descendants = psutil.Process(self.process.pid).children(recursive=True)
                for child in descendants:
                    try: child.kill()
                    except psutil.NoSuchProcess: pass
                psutil.wait_procs(descendants, timeout=5)
            except ImportError:
                pass
            self.process.kill(); self.process.wait(timeout=10)
        for pipe in (self.process.stdin, self.process.stdout):
            if pipe: pipe.close()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('dataset', type=Path); p.add_argument('--manifest', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--split', choices=['train', 'val', 'test'], action='append', help='evaluate only these splits (repeatable)')
    a = p.parse_args(); rows = validate(read_jsonl(a.dataset))
    if a.split: rows = [r for r in rows if r['split'] in a.split]
    model = LocalModel(a.manifest)
    try:
        write_jsonl(a.output, (model.predict(row) for row in rows))
    finally:
        model.close()
    print(f"Saved {len(rows)} local predictions; gold labels and review status unchanged.")


if __name__ == '__main__':
    main()
