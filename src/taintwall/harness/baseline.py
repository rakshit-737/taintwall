"""The frozen baseline: per-attack outcome against the undefended agent.

Scoped to the deterministic track on purpose. Real-model outcomes are stochastic,
so a frozen per-attack baseline would flap on temperature and on silent
model-version drift; those are stored as n-of-k counts elsewhere. Here, when a
Phase 2 heuristic starts blocking an attack, the change shows up as a single
line in the baseline diff (``TW-F1-0003: succeeds -> blocked``) and the strict
xfail test forces that update into the same PR.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from taintwall.corpus.loader import load_attacks
from taintwall.harness.runner import ModelKind, run_matrix
from taintwall.tasks.definitions import by_id

BASELINE_PATH = Path(__file__).resolve().parents[3] / "baselines" / "naive_agent.json"

# A single-read task: the injected carrier is the last thing the agent reads, so a
# pattern-matchable payload actually gets a chance to fire. A multi-read task with
# the injection in a non-final read would report every attack as blocked - an
# artifact of read order, not of any defense.
_BASELINE_TASK = "T-002-page-summary"


@lru_cache(maxsize=1)
def current_outcomes() -> dict[str, str]:
    """Per-attack outcome against the undefended agent (deterministic track).

    "succeeds" here means the *scripted* planner obeyed the payload; it is not the
    corpus's real-model baseline_outcome label. Families that defeat pattern
    matching (F2, F3a, F8) are expected to read as "blocked" on this track even
    though a real model would obey them - that gap is the whole reason the
    reporter refuses to print a scripted attack-success rate.
    """
    outcomes = run_matrix(
        tasks=(by_id(_BASELINE_TASK),),
        attacks=load_attacks(),
        stack_labels=("none",),
        model_kind=ModelKind.FAKE,
    )
    return {
        outcome.attack_id: ("succeeds" if outcome.attack_succeeded else "blocked")
        for outcome in outcomes
        if outcome.attack_id is not None
    }


def load_baseline() -> dict[str, str]:
    data = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    records: dict[str, str] = data["records"]
    return records


def write_baseline(outcomes: dict[str, str]) -> None:
    BASELINE_PATH.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "model": "fake",
        "note": (
            "Deterministic track only. Real-model outcomes are stochastic and are "
            "stored as n-of-k counts elsewhere; a frozen per-attack baseline would flap."
        ),
        "records": dict(sorted(outcomes.items())),
    }
    BASELINE_PATH.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8", newline="\n")
