from __future__ import annotations

import pytest

from taintwall.corpus.loader import load_attacks
from taintwall.corpus.schema import AttackRecord, Family
from taintwall.harness.baseline import current_outcomes, load_baseline

ATTACKS = load_attacks()


def test_baseline_covers_every_attack_record() -> None:
    baseline = load_baseline()
    missing = [r.id for r in ATTACKS if r.id not in baseline]
    assert missing == [], f"baseline is stale; run `taintwall bench --update-baseline`: {missing}"


@pytest.mark.parametrize("record", ATTACKS, ids=lambda r: r.id)
def test_current_outcome_matches_the_frozen_baseline(record: AttackRecord) -> None:
    # When a Phase 2 heuristic changes an outcome, this fails until the baseline
    # is regenerated in the same PR - so a review diff reads, literally,
    # "TW-F1-0003: succeeds -> blocked".
    assert current_outcomes()[record.id] == load_baseline()[record.id]


def test_the_scripted_track_actually_fires_some_attacks() -> None:
    # If nothing succeeds, the harness is not exercising anything and every later
    # number is vacuous.
    succeeded = [i for i, o in current_outcomes().items() if o == "succeeds"]
    assert len(succeeded) >= 20


def test_client_render_family_never_fires_on_the_scripted_track() -> None:
    # F4 leaks only when a *client* renders emitted markup; the agent makes no
    # sink call, so the deterministic track must record every F4 record blocked.
    outcomes = current_outcomes()
    f4 = [r.id for r in ATTACKS if r.family is Family.F4]
    assert f4
    assert all(outcomes[i] == "blocked" for i in f4)


def test_the_scripted_track_has_a_documented_blind_spot() -> None:
    # The invisible-codepoint and confused-deputy families largely defeat pattern
    # matching, so the scripted planner blocks most of them even though a real
    # model would obey. This gap is why the reporter refuses a scripted ASR.
    outcomes = current_outcomes()
    blind = [
        r.id for r in ATTACKS if r.family in {Family.F3A, Family.F8} and outcomes[r.id] == "blocked"
    ]
    assert blind, "expected some F3a/F8 records to slip past the naive planner"
