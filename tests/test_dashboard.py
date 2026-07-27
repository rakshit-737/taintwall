from __future__ import annotations

from pathlib import Path

from taintwall.cli import main
from taintwall.dashboard import gather_data, render_dashboard


def test_gathered_data_has_all_five_stacks() -> None:
    data = gather_data()
    assert [s.label for s in data.stacks] == ["none", "+L1", "+L1L2", "+L1L2L3", "+all"]


def test_the_thesis_holds_in_the_data() -> None:
    data = gather_data()
    stacks = {s.label: s for s in data.stacks}
    # Content layers do not reduce exfiltration; the action + provenance layers do.
    assert stacks["+L1"].exfiltration >= stacks["none"].exfiltration - 0.01
    assert stacks["+L1L2L3"].exfiltration < stacks["none"].exfiltration
    assert stacks["+all"].exfiltration <= stacks["+L1L2L3"].exfiltration
    # Utility never collapses.
    assert all(s.utility >= 0.99 for s in data.stacks if s.label in {"+L1L2L3", "+all"})


def test_render_is_self_contained_html() -> None:
    html = render_dashboard(gather_data())
    assert html.startswith("<!doctype html>")
    # No external resource references.
    assert "http://" not in html
    assert "src=" not in html
    assert "cdn" not in html.lower()
    assert "<svg" in html


def test_render_is_theme_aware() -> None:
    html = render_dashboard(gather_data())
    assert "prefers-color-scheme: dark" in html
    assert 'data-theme="dark"' in html


def test_dashboard_command_writes_a_file(tmp_path: Path) -> None:
    out = tmp_path / "dash.html"
    assert main(["dashboard", "--out", str(out)]) == 0
    text = out.read_text(encoding="utf-8")
    assert "taintwall" in text
    assert "<svg" in text
