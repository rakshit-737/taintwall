from __future__ import annotations

import pytest

from taintwall.corpus.loader import load_attacks
from taintwall.harness.runner import ModelKind, run_matrix
from taintwall.layers.composition import ABLATION_LABELS
from taintwall.tasks.definitions import TASKS


def test_matrix_covers_every_combination() -> None:
    tasks = TASKS[:2]
    attacks = load_attacks()[:3]

    outcomes = run_matrix(
        tasks=tasks, attacks=attacks, stack_labels=ABLATION_LABELS, model_kind=ModelKind.FAKE
    )

    # Each stack sees one clean run per task plus one run per (task, attack).
    expected = len(ABLATION_LABELS) * (len(tasks) + len(tasks) * len(attacks))
    assert len(outcomes) == expected


def test_clean_runs_carry_no_attack_id() -> None:
    outcomes = run_matrix(
        tasks=TASKS[:1],
        attacks=load_attacks()[:1],
        stack_labels=("none",),
        model_kind=ModelKind.FAKE,
    )
    clean = [o for o in outcomes if o.attack_id is None]
    assert clean
    assert all(o.attack_succeeded is False for o in clean)


def test_clean_runs_succeed_and_do_not_exfiltrate() -> None:
    outcomes = run_matrix(
        tasks=TASKS[:3], attacks=(), stack_labels=("none",), model_kind=ModelKind.FAKE
    )
    assert all(o.task_succeeded for o in outcomes)


def test_some_attacks_succeed_against_the_undefended_agent() -> None:
    # Sanity: the deterministic track must show the undefended agent actually
    # obeying at least one attack, or the harness is not exercising anything.
    outcomes = run_matrix(
        tasks=TASKS[:5],
        attacks=load_attacks(),
        stack_labels=("none",),
        model_kind=ModelKind.FAKE,
    )
    attacked = [o for o in outcomes if o.attack_id is not None]
    assert any(o.attack_succeeded for o in attacked)


def test_latency_is_recorded_for_every_case() -> None:
    outcomes = run_matrix(
        tasks=TASKS[:1],
        attacks=load_attacks()[:2],
        stack_labels=("none",),
        model_kind=ModelKind.FAKE,
    )
    assert all(o.latency_ms >= 0.0 for o in outcomes)


def test_real_model_is_not_driven_from_the_matrix() -> None:
    with pytest.raises(NotImplementedError, match="claude_runner"):
        run_matrix(tasks=TASKS[:1], attacks=(), stack_labels=("none",), model_kind=ModelKind.REAL)
