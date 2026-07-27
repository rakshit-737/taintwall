"""Fill in `payload_sha256: "AUTO"` placeholders across the attack corpus.

Authoring a record by hand means computing a SHA-256 over decoded UTF-8 bytes,
which is exactly the kind of manual step that goes wrong quietly. Authors write
``payload_sha256: "AUTO"`` instead and run this script; it substitutes the real
digest positionally, leaving every other byte of the file untouched.

Usage:
    uv run python tools/rehash_corpus.py            # rewrite AUTO placeholders
    uv run python tools/rehash_corpus.py --check    # fail if any AUTO remains
"""

from __future__ import annotations

import argparse
import base64
import re
import sys
from pathlib import Path

import yaml

from taintwall.corpus.loader import ATTACKS_DIR, BENIGN_DIR, compute_sha256

# Match payload_sha256: "AUTO" and the unquoted payload_sha256: AUTO that a YAML
# dumper emits, so authoring by hand and generating with PyYAML both work.
_PLACEHOLDER_RE = re.compile(r'payload_sha256:\s*"?AUTO"?')


def _decoded_payloads(text: str) -> list[str]:
    data = yaml.safe_load(text)
    payloads: list[str] = []
    for record in data["records"]:
        stored = str(record["payload"])
        if record["payload_encoding"] == "base64":
            payloads.append(base64.b64decode(stored, validate=True).decode("utf-8"))
        else:
            payloads.append(stored)
    return payloads


def rehash_file(path: Path) -> int:
    text = path.read_text(encoding="utf-8")
    matches = list(_PLACEHOLDER_RE.finditer(text))
    if not matches:
        return 0

    payloads = _decoded_payloads(text)
    if len(matches) != len(payloads):
        raise SystemExit(
            f"{path}: {len(matches)} AUTO placeholders but {len(payloads)} records. "
            "Every record must use AUTO, or none."
        )

    payload_iter = iter(payloads)

    def _replace(_: re.Match[str]) -> str:
        return f'payload_sha256: "{compute_sha256(next(payload_iter))}"'

    path.write_text(_PLACEHOLDER_RE.sub(_replace, text), encoding="utf-8", newline="\n")
    return len(payloads)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="rehash_corpus")
    parser.add_argument("--check", action="store_true", help="fail if any AUTO remains")
    args = parser.parse_args(argv)

    files = sorted(ATTACKS_DIR.glob("*.yaml")) + sorted(BENIGN_DIR.glob("*.yaml"))
    if args.check:
        stale = [p for p in files if _PLACEHOLDER_RE.search(p.read_text(encoding="utf-8"))]
        for path in stale:
            print(f"unresolved AUTO placeholder: {path}", file=sys.stderr)
        return 1 if stale else 0

    total = 0
    for path in files:
        filled = rehash_file(path)
        if filled:
            print(f"{path.name}: filled {filled} hashes")
        total += filled
    print(f"{total} hashes written")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
