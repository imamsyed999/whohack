"""Explicit opt-in SHA-256 lookup. Never accepts a file or uploads its contents.

Set VIRUSTOTAL_API_KEY yourself. The service never invokes this helper by default.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import time
import urllib.error
import urllib.request

from update import atomic_json

TTL = 7 * 24 * 3600
MAX_RESPONSE = 2 * 1024 * 1024
MAX_CACHE = 5000


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("VirusTotal redirect refused")


@contextmanager
def locked(root: Path):
    root.mkdir(parents=True, exist_ok=True)
    with (root / "lookup.lock").open("a+b") as handle:
        if os.name == "nt":
            import msvcrt
            handle.seek(0)
            if not handle.read(1):
                handle.write(b"0")
                handle.flush()
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            yield
        finally:
            if os.name == "nt":
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def read_json(path: Path, default):
    if not path.exists():
        return default
    with path.open("rb") as handle:
        raw = handle.read(4 * 1024 * 1024 + 1)
    if len(raw) > 4 * 1024 * 1024:
        raise ValueError("lookup cache exceeds 4 MiB")
    return json.loads(raw)


def request_hash(sha256: str, key: str):
    # Fixed origin and GET-only endpoint: no URLs, paths, names or bytes can be sent.
    req = urllib.request.Request("https://www.virustotal.com/api/v3/files/" + sha256,
                                 headers={"x-apikey": key, "Accept": "application/json"}, method="GET")
    try:
        with urllib.request.build_opener(NoRedirect()).open(req, timeout=15) as response:
            raw = response.read(MAX_RESPONSE + 1)
        if len(raw) > MAX_RESPONSE:
            raise ValueError("VirusTotal response exceeds 2 MiB")
        return json.loads(raw)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        if error.code == 429:
            raise ValueError("VirusTotal rate limit reached; retry later") from None
        # Do not print headers, credentials or response bodies in diagnostics.
        raise ValueError(f"VirusTotal HTTP {error.code}") from None


def lookup(sha256: str, root: Path, key: str, *, opt_in: bool, now=None, transport=request_hash):
    if not opt_in:
        raise ValueError("VirusTotal lookup requires explicit --opt-in")
    if not re.fullmatch(r"[a-fA-F0-9]{64}", sha256):
        raise ValueError("provide a SHA-256 digest, never a file path")
    if not key.strip() or any(c in key for c in "\r\n"):
        raise ValueError("set your own VIRUSTOTAL_API_KEY")
    sha256 = sha256.lower()
    now = int(time.time()) if now is None else int(now)
    with locked(root):
        cache = read_json(root / "cache.json", {})
        if not isinstance(cache, dict) or len(cache) > MAX_CACHE:
            raise ValueError("invalid lookup cache")
        cache = {k: v for k, v in cache.items() if isinstance(v, dict) and type(v.get("looked_up_at")) is int and 0 <= now - v["looked_up_at"] < TTL}
        if sha256 in cache:
            return dict(cache[sha256], cached=True)
        calls = read_json(root / "rate.json", [])
        if not isinstance(calls, list) or len(calls) > 500 or any(type(t) is not int for t in calls):
            raise ValueError("invalid lookup rate history")
        if any(t > now for t in calls):
            raise ValueError("clock moved backwards; rate budget cannot be verified")
        calls = [t for t in calls if now - t < 24 * 3600]
        if len(calls) >= 500 or sum(now - t < 60 for t in calls) >= 4:
            raise ValueError("local VirusTotal budget reached (4/minute, 500/day)")
        calls.append(now)
        atomic_json(root / "rate.json", calls)  # count failures too; reserve before I/O
        raw = transport(sha256, key)
        result = {"sha256": sha256, "looked_up_at": now, "found": raw is not None, "stats": {}, "reputation": None, "analysis_at": None}
        if raw is not None:
            data = raw.get("data", {})
            if data.get("id") != sha256 or data.get("type") != "file":
                raise ValueError("VirusTotal returned a different object")
            attributes = data.get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            if not isinstance(stats, dict) or any(type(v) is not int or not 0 <= v <= 10000 for v in stats.values()):
                raise ValueError("invalid analysis counts")
            allowed = {"malicious", "suspicious", "harmless", "undetected", "timeout", "confirmed-timeout", "failure", "type-unsupported"}
            result["stats"] = {k: v for k, v in stats.items() if k in allowed}
            for source, dest in [("reputation", "reputation"), ("last_analysis_date", "analysis_at")]:
                value = attributes.get(source)
                if type(value) is int:
                    result[dest] = value
        if len(cache) >= MAX_CACHE:
            del cache[min(cache, key=lambda k: cache[k]["looked_up_at"])]
        cache[sha256] = result
        atomic_json(root / "cache.json", cache)
        return dict(result, cached=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sha256")
    parser.add_argument("--opt-in", action="store_true")
    parser.add_argument("--cache-dir", type=Path, default=Path(".vigil/virustotal"))
    args = parser.parse_args()
    try:
        print(json.dumps(lookup(args.sha256, args.cache_dir, os.environ.get("VIRUSTOTAL_API_KEY", ""), opt_in=args.opt_in), indent=2))
    except (OSError, ValueError) as error:
        parser.exit(1, f"whohack: {error}\n")


if __name__ == "__main__":
    main()
