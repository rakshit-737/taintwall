from __future__ import annotations

import pytest

from taintwall.harness.metrics import Proportion
from taintwall.harness.report import (
    ASR_UNAVAILABLE,
    CellReport,
    build_reports,
    render_markdown,
)
from taintwall.harness.runner import CaseOutcome, ModelKind

OUTCOMES = (
    CaseOutcome("T-001", None, None, "none", True, False, 1.0),
    CaseOutcome("T-001", "TW-F1-0001", "F1", "none", False, True, 2.0),
    CaseOutcome("T-001", "TW-F2-0001", "F2", "none", True, False, 3.0),
)


def test_asr_is_none_under_the_scripted_planner() -> None:
    (report,) = build_reports(OUTCOMES, model_kind=ModelKind.FAKE)
    assert report.asr is None
    assert all(v is None for v in report.per_family_asr.values())


def test_benign_utility_uses_only_clean_runs() -> None:
    (report,) = build_reports(OUTCOMES, model_kind=ModelKind.FAKE)
    assert report.benign_utility == Proportion(1, 1)


def test_utility_under_attack_uses_only_attacked_runs() -> None:
    (report,) = build_reports(OUTCOMES, model_kind=ModelKind.FAKE)
    assert report.utility_under_attack == Proportion(1, 2)


def test_exfiltration_is_reported_even_under_the_scripted_planner() -> None:
    # Unlike ASR, the exfiltration count is an observed sink-call rate and is
    # reported on the scripted track (its cross-stack delta is the Layer 3 signal).
    (report,) = build_reports(OUTCOMES, model_kind=ModelKind.FAKE)
    assert report.exfiltration == Proportion(1, 2)


def test_exfiltration_appears_in_the_rendered_table() -> None:
    text = render_markdown(
        build_reports(OUTCOMES, model_kind=ModelKind.FAKE), model_kind=ModelKind.FAKE
    )
    assert "exfiltration" in text


def test_real_model_computes_a_real_asr() -> None:
    (report,) = build_reports(OUTCOMES, model_kind=ModelKind.REAL)
    assert report.asr == Proportion(1, 2)
    assert report.per_family_asr["F1"] == Proportion(1, 1)
    assert report.per_family_asr["F2"] == Proportion(0, 1)


def test_markdown_prints_the_guardrail_string_not_a_number() -> None:
    reports = build_reports(OUTCOMES, model_kind=ModelKind.FAKE)
    text = render_markdown(reports, model_kind=ModelKind.FAKE)
    assert ASR_UNAVAILABLE in text


def test_rendering_a_fake_run_with_a_populated_asr_is_refused() -> None:
    bad = CellReport(
        stack_label="none",
        benign_utility=Proportion(1, 1),
        utility_under_attack=Proportion(1, 2),
        asr=Proportion(1, 2),
        exfiltration=Proportion(1, 2),
        per_family_asr={},
        latency_p50_ms=1.0,
        latency_p95_ms=3.0,
    )
    with pytest.raises(ValueError, match="scripted"):
        render_markdown((bad,), model_kind=ModelKind.FAKE)


def test_latency_percentiles_are_reported() -> None:
    (report,) = build_reports(OUTCOMES, model_kind=ModelKind.FAKE)
    assert report.latency_p50_ms > 0
    assert report.latency_p95_ms >= report.latency_p50_ms


def test_fpr_is_rendered_when_supplied() -> None:
    reports = build_reports(OUTCOMES, model_kind=ModelKind.REAL)
    text = render_markdown(reports, model_kind=ModelKind.REAL, fpr=Proportion(3, 100))
    assert "False-positive rate" in text
    assert "n=100" in text
