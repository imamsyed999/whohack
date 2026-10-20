#!/usr/bin/env python3
"""No dependencies; validates the harmless generator and its cleanup."""
import io
import json
from pathlib import Path
import unittest
from beacon_sim import simulate


class BeaconTests(unittest.TestCase):
    def test_local_only_fixture_and_cleanup(self):
        output = io.StringIO()
        simulate(output, fast=True)
        records = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(len(records), 7)
        connections = [r["event"] for r in records if r["event"]["kind"]["type"] == "net_connect"]
        self.assertEqual(len(connections), 4)
        self.assertEqual({e["kind"]["remote_ip"] for e in connections}, {"127.0.0.1"})
        self.assertEqual([connections[i + 1]["ts"] - connections[i]["ts"] for i in range(3)], [5000] * 3)
        self.assertEqual(len(records[0]["process"]["exe"]["sha256"]), 64)
        dummy = next(r["event"]["kind"]["path"] for r in records if r["event"]["kind"]["type"] == "file_access")
        self.assertFalse(Path(dummy).parent.exists(), "temporary files must be removed")

    def test_invalid_intervals(self):
        for interval in [-1, 0, 1, 4000]:
            with self.assertRaises(ValueError):
                simulate(io.StringIO(), interval=interval, fast=True)


if __name__ == "__main__":
    unittest.main()
