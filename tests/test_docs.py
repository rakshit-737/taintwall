from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    "name",
    ["README.md", "SECURITY.md", "KNOWN_BYPASSES.md", "CITATION.cff", "LICENSE"],
)
def test_required_file_exists(name: str) -> None:
    assert (ROOT / name).is_file()


@pytest.mark.parametrize(
    "name",
    [".github/ISSUE_TEMPLATE/attack-submission.yml", ".github/ISSUE_TEMPLATE/false-positive.yml"],
)
def test_issue_form_exists(name: str) -> None:
    assert (ROOT / name).is_file()


def test_readme_has_a_threat_model_and_non_goals_section() -> None:
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "## Threat model" in text
    assert "## Non-goals" in text


def test_readme_names_the_prior_art_it_competes_with() -> None:
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    for name in ("Pipelock", "Rebuff", "LLM Guard"):
        assert name in text, f"README does not name {name}"


def test_known_bypasses_opens_with_the_taint_limitation() -> None:
    text = (ROOT / "KNOWN_BYPASSES.md").read_text(encoding="utf-8")
    assert "KB-001" in text
    assert "2604.23374" in text


def test_security_policy_distinguishes_the_three_report_types() -> None:
    text = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    assert "bypass of taintwall" in text.lower()
    assert "new attack technique" in text.lower()
    assert "inert" in text.lower()


def test_attack_form_requires_the_inclusion_criterion_attestation() -> None:
    text = (ROOT / ".github/ISSUE_TEMPLATE/attack-submission.yml").read_text(encoding="utf-8")
    assert "injection mechanism" in text
    assert "source_license" in text
