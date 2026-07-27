from __future__ import annotations

import pytest

from taintwall.harness.metrics import Proportion, aggregate


def test_rate_is_successes_over_trials() -> None:
    assert Proportion(3, 4).rate == pytest.approx(0.75)


def test_zero_trials_reports_a_full_width_interval() -> None:
    assert Proportion(0, 0).ci95() == (0.0, 1.0)


def test_wilson_interval_brackets_the_point_estimate() -> None:
    low, high = Proportion(7, 10).ci95()
    assert low < 0.7 < high
    assert low >= 0.0
    assert high <= 1.0


def test_small_samples_produce_wider_intervals() -> None:
    narrow = Proportion(70, 100).ci95()
    wide = Proportion(7, 10).ci95()
    assert (wide[1] - wide[0]) > (narrow[1] - narrow[0])


def test_format_includes_n_so_no_cell_is_quoted_without_it() -> None:
    text = Proportion(7, 10).format()
    assert "n=10" in text
    assert "%" in text


def test_aggregate_groups_by_key() -> None:
    rows = [("F1", True), ("F1", False), ("F2", True)]
    result = aggregate(rows, key=lambda row: row[0], success=lambda row: row[1])
    assert result["F1"] == Proportion(1, 2)
    assert result["F2"] == Proportion(1, 1)
