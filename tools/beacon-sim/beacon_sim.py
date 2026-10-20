#!/usr/bin/env python3
"""Harmless, localhost-only fixture generator. Never touches real credential stores.

Default: four real connections five seconds apart. --fast keeps the same logical
timestamps but removes the waits, for deterministic offline replay and CI.
Output contains declared fixture metadata, not telemetry from an OS collector.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import tempfile
import time


def simulate(output, interval=5.0, fast=False):
    if interval < 5 or interval > 3600:
        raise ValueError("interval must be between 5 and 3600 seconds")
    with tempfile.TemporaryDirectory(prefix="whohack-beacon-") as directory:
        root = Path(directory)
        dummy = root / "Login Data"
        dummy.write_text("whohack harmless dummy data\n", encoding="utf-8")
        pid = os.getpid()
        start = int(time.time() * 1000)
        process = {
            "pid": pid, "ppid": os.getppid(), "start_time": start,
            "exe": {"path": str(root / "Downloads" / "demo-reader"),
                    "sha256": hashlib.sha256(b"whohack harmless replay app").hexdigest(),
                    "origin": {"type": "downloaded", "url": None, "referrer": None},
                    "sign": {"type": "unsigned"}, "yara_hits": [], "first_seen": start},
            "script": None, "path_class": "downloads", "tainted": True,
            "taint_root": pid, "app_id": "fixture:whohack-beacon-reader",
        }

        def emit(ts, kind):
            output.write(json.dumps({"event": {"ts": ts, "pid": pid, "kind": kind}, "process": process}) + "\n")
            output.flush()

        emit(start, {"type": "process_start", "ppid": os.getppid(), "exe": process["exe"]["path"], "cmdline": None})
        dummy.read_text(encoding="utf-8")
        emit(start, {"type": "file_access", "path": str(dummy), "class": "browser_passwords", "write": False})
        autorun = root / "dummy-autorun.txt"
        autorun.write_text("This file is never registered or executed.\n", encoding="utf-8")
        emit(start, {"type": "persistence", "location": "autostart", "target": str(autorun)})
        with socket.socket() as server:
            server.bind(("127.0.0.1", 0))
            server.listen(1)
            server.settimeout(5)
            port = server.getsockname()[1]
            for index in range(4):
                if index and not fast:
                    time.sleep(interval)
                with socket.create_connection(("127.0.0.1", port), timeout=5) as client:
                    conn, _ = server.accept()
                    with conn:
                        client.sendall(b"whohack harmless beacon\n")
                        conn.recv(128)
                emit(start + int(index * interval * 1000), {"type": "net_connect", "remote_ip": "127.0.0.1", "remote_port": port, "proto": "tcp", "domain": None, "dns_before": False})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--interval", type=float, default=5.0)
    parser.add_argument("--fast", action="store_true")
    args = parser.parse_args()
    if not 5 <= args.interval <= 3600:
        parser.error("--interval must be between 5 and 3600 seconds")
    with args.output.open("w", encoding="utf-8") as output:
        simulate(output, args.interval, args.fast)


if __name__ == "__main__":
    main()
