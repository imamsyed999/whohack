"""Opt-in threat metadata updater. Standard library only; never downloads samples.

The daemon consumes intel.json offline. Run this tool once or with --watch.
Keys are read from environment variables and are never written to the cache.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

MAX_BYTES = 48 * 1024 * 1024
MAX_ITEMS = 250_000
PUBLIC = {
    "spamhaus-drop-v4": ("https://www.spamhaus.org/drop/drop_v4.json", "drop"),
    "spamhaus-drop-v6": ("https://www.spamhaus.org/drop/drop_v6.json", "drop"),
    "feodo": ("https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt", "ips"),
}


def atomic_json(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".vigil-intel-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as output:
            json.dump(value, output, separators=(",", ":"))
            output.flush()
            os.fsync(output.fileno())
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def indicator(value: str) -> str:
    value = value.strip().lower().rstrip(".")
    if len(value) > 253:
        raise ValueError("indicator exceeds length limit")
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        labels = value.split(".")
        if len(labels) < 2 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", p) for p in labels):
            raise ValueError("invalid domain indicator") from None
        return value
    if network.prefixlen == 0:
        raise ValueError("refusing a default-route indicator")
    return str(network)


def parse_feed(text: str, kind: str) -> list[str]:
    values = []
    if kind == "drop":
        for line in text.splitlines():
            if line.strip():
                item = json.loads(line)
                if "cidr" in item:
                    values.append(item["cidr"])
                elif item.get("type") != "metadata":
                    raise ValueError("unrecognized DROP record")
    elif kind in ("ips", "hosts", "indicators"):
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            if not line or line.startswith(";"):
                continue
            fields = line.split()
            if kind == "hosts":
                if len(fields) != 2 or fields[0] not in ("0.0.0.0", "127.0.0.1"):
                    raise ValueError("expected a curated URLhaus hosts file")
                if fields[1] in ("localhost", "localhost.localdomain"):
                    continue
                values.append(fields[1])
            else:
                if len(fields) != 1:
                    raise ValueError("expected one indicator per line")
                if kind == "ips":
                    ipaddress.ip_address(fields[0])
                values.append(fields[0])
    elif kind == "threatfox":
        body = json.loads(text)
        if body.get("query_status") == "no_result":
            return []
        if body.get("query_status") != "ok" or not isinstance(body.get("data"), list):
            raise ValueError("ThreatFox did not return a valid result")
        for item in body["data"]:
            # Do not turn URL-path or port-specific evidence into an overly
            # broad host block. Domain IOCs alone fit this snapshot's scope.
            if item.get("ioc_type") == "domain" and int(item.get("confidence_level", 0)) >= 75:
                values.append(item["ioc"])
    else:
        raise ValueError("unknown feed format")
    if len(values) > MAX_ITEMS:
        raise ValueError("feed exceeds indicator limit")
    return sorted({indicator(v) for v in values})


def source_notices(text: str, kind: str) -> list:
    """Retain provider copyright/date/terms separately from detection indicators."""
    if kind == "drop":
        return [item for line in text.splitlines() if line.strip()
                if (item := json.loads(line)).get("type") == "metadata"]
    return [line for line in text.splitlines() if line.startswith(("#", ";"))][:256]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Prevent forwarding keys to a different host or a sample URL.
        return None


def fetch(url: str, cached: dict, headers=None, body=None):
    request_headers = {"User-Agent": "whohack-threat-metadata/0.1", **(headers or {})}
    for key, header in (("etag", "If-None-Match"), ("last_modified", "If-Modified-Since")):
        if cached.get(key):
            request_headers[header] = cached[key]
    req = urllib.request.Request(url, headers=request_headers, data=body)
    try:
        with urllib.request.build_opener(NoRedirect).open(req, timeout=30) as response:
            data = response.read(MAX_BYTES + 1)
            if len(data) > MAX_BYTES:
                raise ValueError("feed exceeds 48 MiB")
            return data.decode("utf-8-sig"), {
                "etag": response.headers.get("ETag"),
                "last_modified": response.headers.get("Last-Modified"),
            }
    except urllib.error.HTTPError as error:
        if error.code == 304 and "values" in cached:
            return None, {k: cached.get(k) for k in ("etag", "last_modified")}
        # Deliberately omit exception strings/URLs: URLhaus embeds a secret.
        raise ValueError(f"provider returned HTTP {error.code}") from None
    except urllib.error.URLError:
        raise ValueError("provider connection failed") from None


def update(args):
    now = int(time.time() * 1000)
    cache_path = args.output.with_name("intel-cache.json")
    cache = json.loads(cache_path.read_text("utf-8")) if cache_path.exists() else {}
    sources = []
    if args.fetch_public:
        sources.extend((name, url, kind, {}, None) for name, (url, kind) in PUBLIC.items())
    if args.threatfox:
        key = os.environ.get("WHOHACK_ABUSECH_AUTH_KEY", "")
        if not key:
            raise ValueError("set WHOHACK_ABUSECH_AUTH_KEY to use ThreatFox")
        sources.append(("threatfox", "https://threatfox-api.abuse.ch/api/v1/", "threatfox", {"Auth-Key": key, "Content-Type": "application/json"}, b'{"query":"get_iocs","days":7}'))
    if args.urlhaus:
        url = os.environ.get("WHOHACK_URLHAUS_HOSTS_URL", "")
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "https" or parsed.hostname != "urlhaus-api.abuse.ch" or not parsed.path.startswith("/v2/files/exports/") or not parsed.path.endswith("/hosts/"):
            raise ValueError("set WHOHACK_URLHAUS_HOSTS_URL to the curated hosts export URL from your provider account")
        sources.append(("urlhaus-hosts", url, "hosts", {}, None))
    errors = []
    for name, url, kind, headers, body in sources:
        previous = cache.get(name, {})
        # Six-hour floor also applies to one-shot invocations.
        if 0 <= now - previous.get("confirmed_at", 0) < 6 * 60 * 60 * 1000:
            continue
        try:
            text, metadata = fetch(url, previous, headers, body)
            values = previous["values"] if text is None else parse_feed(text, kind)
            notices = previous.get("notices", []) if text is None else source_notices(text, kind)
            cache[name] = {**metadata, "values": values, "notices": notices,
                           "confirmed_at": now, "expires_at": now + 48 * 60 * 60 * 1000}
        except (ValueError, OSError):
            errors.append(name)  # Never echo URLs or credential-bearing errors.
    for path, kind in ((args.import_indicators, "indicators"), (args.urlhaus_hosts, "hosts")):
        if path:
            if path.stat().st_size > MAX_BYTES:
                raise ValueError("local feed exceeds 48 MiB")
            name = "local" if kind == "indicators" else "urlhaus-hosts"
            cache[name] = {"values": parse_feed(path.read_text("utf-8-sig"), kind), "confirmed_at": now, "expires_at": now + 48 * 60 * 60 * 1000}
    items = []
    for name, provider in cache.items():
        if provider.get("expires_at", 0) <= now:
            continue
        for value in provider["values"]:
            items.append({"value": indicator(value), "source": name, "expires_at": provider["expires_at"]})
    if len(items) > MAX_ITEMS:
        raise ValueError("combined feeds exceed indicator limit; snapshot retained")
    atomic_json(cache_path, cache)
    # No API keys or credential-bearing URLs belong in attribution files.
    atomic_json(args.output.with_name("intel-sources.json"), {
        name: {"url": PUBLIC[name][0] if name in PUBLIC else None,
               "credit": "Spamhaus DROP data; copyright The Spamhaus Project" if name.startswith("spamhaus-")
                         else "Feodo Tracker, abuse.ch" if name == "feodo" else name,
               "last_modified": provider.get("last_modified"),
               "confirmed_at": provider.get("confirmed_at"), "expires_at": provider.get("expires_at"),
               "provider_notices": provider.get("notices", [])}
        for name, provider in cache.items()})
    atomic_json(args.output, {"version": 1, "fetched_at": now, "indicators": items})
    print(f"Published {len(items)} indicators to {args.output}")
    if errors:
        print("Refresh failed; retained unexpired data for: " + ", ".join(errors), file=sys.stderr)
    return not errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--fetch-public", action="store_true")
    parser.add_argument("--threatfox", action="store_true")
    parser.add_argument("--urlhaus", action="store_true")
    parser.add_argument("--urlhaus-hosts", type=Path)
    parser.add_argument("--import-indicators", type=Path)
    parser.add_argument("--watch", action="store_true", help="refresh every six hours until stopped")
    args = parser.parse_args()
    if not any((args.fetch_public, args.threatfox, args.urlhaus, args.urlhaus_hosts, args.import_indicators)):
        parser.error("choose at least one source; no network activity is enabled by default")
    while True:
        ok = update(args)
        if not args.watch:
            return 0 if ok else 1
        time.sleep(6 * 60 * 60)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
    except (OSError, ValueError) as exc:
        print(f"Threat update failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
