import json
from pathlib import Path
import tempfile
import unittest

from virustotal import lookup, TTL


class LookupTests(unittest.TestCase):
    def test_opt_in_hash_only_cache_expiry_and_privacy(self):
        calls = []
        def fake(sha, key):
            calls.append((sha, key))
            return {"data": {"id": sha, "type": "file", "attributes": {"names": ["private-name"], "last_analysis_stats": {"malicious": 2}, "reputation": -3}}}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for sha, opt_in in [("a" * 64, False), ("C:/private.txt", True)]:
                with self.assertRaises(ValueError):
                    lookup(sha, root, "secret-key", opt_in=opt_in, now=1000, transport=fake)
            self.assertEqual(calls, [])
            first = lookup("a" * 64, root, "secret-key", opt_in=True, now=1000, transport=fake)
            self.assertFalse(first["cached"])
            self.assertTrue(lookup("a" * 64, root, "secret-key", opt_in=True, now=1001, transport=fake)["cached"])
            self.assertEqual(len(calls), 1)
            self.assertFalse(lookup("a" * 64, root, "secret-key", opt_in=True, now=1000 + TTL, transport=fake)["cached"])
            saved = (root / "cache.json").read_text()
            self.assertNotIn("secret-key", saved)
            self.assertNotIn("private-name", saved)

    def test_rate_budget_and_not_found_are_conservative(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for n in range(4):
                result = lookup(f"{n:064x}", root, "key", opt_in=True, now=1000, transport=lambda *_: None)
                self.assertFalse(result["found"])
            with self.assertRaisesRegex(ValueError, "budget"):
                lookup("f" * 64, root, "key", opt_in=True, now=1059, transport=lambda *_: self.fail("over-budget network call"))
            lookup("f" * 64, root, "key", opt_in=True, now=1060, transport=lambda *_: None)
            (root / "rate.json").write_text(json.dumps([1061] * 500))
            with self.assertRaises(ValueError):
                lookup("b" * 64, root, "key", opt_in=True, now=1061, transport=lambda *_: self.fail("daily limit bypass"))


if __name__ == "__main__":
    unittest.main()
