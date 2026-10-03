"""Turns `cargo test` output into GitHub Actions error annotations.

Usage: python tools/ci/annotate_test_failures.py test.log

Each failing test becomes one `::error` annotation whose message is the start
of its captured output (panic message, assertion values). Compile errors are
reported too. Annotations are visible in the GitHub UI and through the public
check-runs API, so failures can be diagnosed without downloading logs.
"""
import re
import sys

MAX_LINES = 12
MAX_ANNOTATIONS = 20


def esc(s: str) -> str:
    return s.replace("%", "%25").replace("\r", "").replace("\n", "%0A")


def main(path: str) -> None:
    text = open(path, encoding="utf-8", errors="replace").read()
    emitted = 0
    # Captured output blocks: "---- name stdout ----" ... until blank line + next block
    for m in re.finditer(r"^---- (\S+) stdout ----\n(.*?)(?=^---- |\nfailures:\n|\Z)", text, re.M | re.S):
        name, body = m.group(1), m.group(2).strip().splitlines()
        msg = "\n".join(body[:MAX_LINES]) or "(no output)"
        print(f"::error title=test failed: {esc(name)}::{esc(msg)}")
        emitted += 1
        if emitted >= MAX_ANNOTATIONS:
            return
    for m in re.finditer(r"^error(\[E\d+\])?: (.*)$\n(.*?)(?=^\S|\Z)", text, re.M | re.S):
        detail = "\n".join(m.group(3).strip().splitlines()[:MAX_LINES])
        print(f"::error title=build error::{esc(m.group(2) + chr(10) + detail)}")
        emitted += 1
        if emitted >= MAX_ANNOTATIONS:
            return
    if emitted == 0:
        tail = "\n".join(text.strip().splitlines()[-MAX_LINES:])
        print(f"::error title=cargo test failed::{esc(tail)}")


if __name__ == "__main__":
    main(sys.argv[1])
