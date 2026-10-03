"""Print name, version and declared license of every distribution installed in the current venv.

    python ml/research/list_licenses.py

Reads only package metadata (License-Expression, License, and License :: classifiers). Anything not
clearly MIT / BSD / Apache / PSF / ISC / MPL is flagged with '!!' for manual review.
"""
import importlib.metadata as md
import re

OK = re.compile(r"\b(MIT|BSD|Apache|PSF|Python Software Foundation|ISC|0BSD|Unlicense|HPND|CC0)\b", re.I)

rows = []
for dist in md.distributions():
    meta = dist.metadata
    name, ver = meta["Name"], dist.version
    expr = meta.get("License-Expression") or ""
    lic = (meta.get("License") or "").strip().splitlines()[0][:60] if meta.get("License") else ""
    classifiers = [c.split("::")[-1].strip() for c in (meta.get_all("Classifier") or []) if c.startswith("License ::")]
    decl = expr or "; ".join(classifiers) or lic or "UNKNOWN"
    flag = "  " if OK.search(decl + " " + lic + " " + " ".join(classifiers)) else "!!"
    rows.append((flag, name, ver, decl))

for flag, name, ver, decl in sorted(rows, key=lambda r: r[1].lower()):
    print(f"{flag} {name:28s} {ver:22s} {decl}")
