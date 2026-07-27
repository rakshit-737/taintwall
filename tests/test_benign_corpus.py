from __future__ import annotations

import pytest

from taintwall.corpus.loader import load_attacks, load_benign
from taintwall.corpus.schema import BenignRecord

BENIGN = load_benign()
_ATTACK_PAYLOADS = {r.payload for r in load_attacks()}
_TRIGGERS = ("ignore", "instruction", "system prompt", "override", "disregard")


def test_hard_negative_stratum_is_populated() -> None:
    hard = [r for r in BENIGN if r.stratum == "hard_negative"]
    assert len(hard) >= 150, f"only {len(hard)} hard negatives"


def test_benign_ids_are_unique() -> None:
    ids = [r.id for r in BENIGN]
    assert len(set(ids)) == len(ids)


@pytest.mark.parametrize("record", BENIGN, ids=lambda r: r.id)
def test_benign_text_is_not_an_attack_payload(record: BenignRecord) -> None:
    assert record.text not in _ATTACK_PAYLOADS


def test_trigger_words_are_well_represented() -> None:
    hits = sum(any(t in r.text.lower() for t in _TRIGGERS) for r in BENIGN)
    assert hits >= 40, f"only {hits} records contain trigger words; FPR would be untested"
