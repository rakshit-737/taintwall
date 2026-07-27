from __future__ import annotations

from pathlib import Path

import pytest

from taintwall.cli import main


def test_corpus_validate_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["corpus", "validate"]) == 0
    out = capsys.readouterr().out
    assert "attack records" in out
    assert "benign records" in out


def test_bench_writes_a_markdown_report(tmp_path: Path) -> None:
    out = tmp_path / "report.md"
    assert main(["bench", "--model", "fake", "--limit-attacks", "3", "--out", str(out)]) == 0
    text = out.read_text(encoding="utf-8")
    assert "N/A (scripted)" in text
    assert "| `none` |" in text


def test_bench_rejects_real_model_without_the_ack_flag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("TAINTWALL_DEMO_ACK", raising=False)
    assert main(["bench", "--model", "real"]) == 2


def test_corpus_export_writes_one_jsonl_line_per_record(tmp_path: Path) -> None:
    out = tmp_path / "attacks.jsonl"
    assert main(["corpus", "export", "--out", str(out)]) == 0
    lines = out.read_text(encoding="utf-8").splitlines()
    assert len(lines) >= 112


def test_export_is_ascii_clean_so_invisible_payloads_survive(tmp_path: Path) -> None:
    # Base64 payloads decode to invisible characters; the JSONL must be ASCII so
    # those bytes are not silently mangled by a downstream editor.
    out = tmp_path / "attacks.jsonl"
    main(["corpus", "export", "--out", str(out)])
    raw = out.read_bytes()
    assert raw.decode("ascii")  # raises if any non-ASCII byte slipped through
