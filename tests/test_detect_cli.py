from __future__ import annotations

import pytest

from taintwall.cli import main


def test_detect_command_reports_layer1_efficacy(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["detect"]) == 0
    out = capsys.readouterr().out
    assert "Layer 1 detection" in out
    assert "invisible-codepoint attacks (F3a) flagged" in out
    assert "hidden-markup attacks (F3b) flagged" in out
    assert "false positive" in out
