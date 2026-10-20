import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class PrepareTests(unittest.TestCase):
    def test_laya_requires_explicit_migration_then_pins_nested_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); model = root / 'model'; output = root / 'manifest.json'
            for name in ['rl_agent_config.json', 'encoder/config.json', 'tokenizer/tokenizer.json', 'model.safetensors']:
                path = model / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text('{}')
            cfg = model / 'tokenizer/tokenizer_config.json'
            cfg.write_text(json.dumps({'tokenizer_class': 'TokenizersBackend', 'extra_special_tokens': ['<fixture>']}))
            command = [sys.executable, str(Path(__file__).with_name('prepare_model.py')), '--backend', 'laya', '--model-dir', str(model),
                       '--python', sys.executable, '--revision', 'fake-fixture', '--output', str(output)]
            first = subprocess.run(command, capture_output=True, text=True, timeout=10)
            self.assertNotEqual(first.returncode, 0); self.assertIn('compatibility migration', first.stderr)
            self.assertFalse(output.exists())
            subprocess.run(command + ['--normalize-laya-tokenizer'], capture_output=True, check=True, timeout=10)
            result = json.loads(output.read_text()); normalized = json.loads(cfg.read_text())
            self.assertEqual(result['dtype'], 'float32')
            self.assertEqual(normalized['tokenizer_class'], 'PreTrainedTokenizerFast')
            self.assertEqual(normalized['extra_special_tokens'], {'extra_0': '<fixture>'})
            self.assertEqual(result['files']['tokenizer/tokenizer_config.json'], hashlib.sha256(cfg.read_bytes()).hexdigest())
            (model / 'extra.PY').write_text('# never executed')
            refused = subprocess.run(command, capture_output=True, text=True, timeout=10)
            self.assertNotEqual(refused.returncode, 0); self.assertIn('pickle files', refused.stderr)


if __name__ == '__main__':
    unittest.main()
