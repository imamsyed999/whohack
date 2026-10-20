import json
import unittest
from update import indicator, parse_feed, source_notices


class FeedTests(unittest.TestCase):
    def test_current_drop_format(self):
        text = '{"cidr":"192.0.2.0/24","sblid":"SBL-test"}\n{"type":"metadata","timestamp":1}\n'
        self.assertEqual(parse_feed(text, "drop"), ["192.0.2.0/24"])
        metadata = {"type": "metadata", "timestamp": 123, "copyright": "Provider copyright", "terms": "https://example.invalid/terms"}
        self.assertEqual(source_notices(text + json.dumps(metadata), "drop"),
                         [{"type": "metadata", "timestamp": 1}, metadata])
        self.assertEqual(source_notices("# Provider date and copyright\n192.0.2.1\n", "ips"),
                         ["# Provider date and copyright"])

    def test_scope_is_not_widened_from_urls_or_ports(self):
        data = {"query_status": "ok", "data": [
            {"ioc_type": "url", "ioc": "https://shared.example/bad", "confidence_level": 100},
            {"ioc_type": "ip:port", "ioc": "192.0.2.1:443", "confidence_level": 100},
            {"ioc_type": "domain", "ioc": "evil.example", "confidence_level": 90},
        ]}
        self.assertEqual(parse_feed(json.dumps(data), "threatfox"), ["evil.example"])

    def test_rejects_malformed_and_default_route(self):
        for value in ("0.0.0.0/0", "::/0", "https://bad.example/x", "bad..example", "<html>"):
            with self.assertRaises(ValueError):
                indicator(value)
        self.assertEqual(parse_feed("# empty feed is valid\n", "ips"), [])
        self.assertEqual(parse_feed("0.0.0.0 bad.example\n", "hosts"), ["bad.example"])


if __name__ == "__main__":
    unittest.main()
