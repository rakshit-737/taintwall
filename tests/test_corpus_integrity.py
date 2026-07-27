"""CI gate over the whole labelled corpus.

Every check here is a promise the README makes to a reader: hashes are real,
targets are inert, ids are unique even on a case-insensitive filesystem, every
record is attributed, and no family ships without an adaptive variant.
"""

from __future__ import annotations

import ipaddress
import re
from collections import Counter

import pytest

from taintwall.corpus.loader import compute_sha256, load_attacks
from taintwall.corpus.schema import AttackRecord

ATTACKS = load_attacks()

_ALLOWED_SUFFIXES = (
    ".invalid",
    ".example",
    "example.com",
    "example.org",
    "example.net",
)
_ALLOWED_NETWORKS = tuple(
    ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)
_HOST_RE = re.compile(r"(?:https?://|@)([A-Za-z0-9._-]+)")


def _host_is_inert(host: str) -> bool:
    host = host.rstrip(".").lower()
    if host in {"localhost", "127.0.0.1"}:
        return True
    if host.endswith(_ALLOWED_SUFFIXES):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(address in network for network in _ALLOWED_NETWORKS)


def test_corpus_is_not_empty() -> None:
    assert ATTACKS, "no attack records loaded"


@pytest.mark.parametrize("record", ATTACKS, ids=lambda r: r.id)
def test_payload_hash_matches(record: AttackRecord) -> None:
    assert compute_sha256(record.payload) == record.payload_sha256


@pytest.mark.parametrize("record", ATTACKS, ids=lambda r: r.id)
def test_targets_are_inert(record: AttackRecord) -> None:
    bad = [h for h in _HOST_RE.findall(record.payload) if not _host_is_inert(h)]
    assert not bad, f"{record.id} references live host(s): {bad}"


@pytest.mark.parametrize("record", ATTACKS, ids=lambda r: r.id)
def test_source_is_attributed(record: AttackRecord) -> None:
    assert record.source.name and record.source.url and record.source.license


@pytest.mark.parametrize("record", ATTACKS, ids=lambda r: r.id)
def test_id_follows_the_naming_scheme(record: AttackRecord) -> None:
    assert re.fullmatch(r"TW-F\d[AB]?-\d{4}", record.id), record.id


def test_ids_are_unique_case_insensitively() -> None:
    counts = Counter(r.id.lower() for r in ATTACKS)
    assert [i for i, c in counts.items() if c > 1] == []


def test_every_family_has_an_adaptive_variant() -> None:
    families = {r.family for r in ATTACKS}
    adaptive = {r.family for r in ATTACKS if r.adaptive}
    missing = families - adaptive
    assert missing == set(), f"families with no adaptive variant: {sorted(f.value for f in missing)}"


def test_no_unresolved_hash_placeholder_remains() -> None:
    assert [r.id for r in ATTACKS if r.payload_sha256 == "AUTO"] == []
