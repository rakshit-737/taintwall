"""Measure Layer 1's detection efficacy directly against the labelled corpora.

Layer 1 is not evaluated through the ablation attack-success rate — the scripted
planner cannot exhibit the obfuscation Layer 1 defeats (see the Phase 2 design).
It is evaluated here: true-positive rate on the invisible-codepoint family, and
false-positive rate on the benign corpus.
"""

from __future__ import annotations

from dataclasses import dataclass

from taintwall.corpus.loader import load_attacks, load_benign
from taintwall.corpus.schema import Family
from taintwall.harness.metrics import Proportion
from taintwall.normalize import detect


@dataclass(frozen=True, slots=True)
class DetectionReport:
    codepoint_family_tpr: Proportion
    all_attacks_flagged: Proportion
    benign_false_positive: Proportion


def evaluate_layer1() -> DetectionReport:
    attacks = load_attacks()
    benign = load_benign()

    f3a = [r for r in attacks if r.family is Family.F3A]
    f3a_hits = sum(1 for r in f3a if detect(r.payload))
    all_hits = sum(1 for r in attacks if detect(r.payload))
    benign_hits = sum(1 for r in benign if detect(r.text))

    return DetectionReport(
        codepoint_family_tpr=Proportion(f3a_hits, len(f3a)),
        all_attacks_flagged=Proportion(all_hits, len(attacks)),
        benign_false_positive=Proportion(benign_hits, len(benign)),
    )


def render_detection_markdown(report: DetectionReport) -> str:
    tpr = report.codepoint_family_tpr.format()
    total = report.all_attacks_flagged.format()
    fpr = report.benign_false_positive.format()
    return "\n".join(
        [
            "# Layer 1 detection (normalization)",
            "",
            "| metric | value |",
            "|---|---|",
            f"| invisible-codepoint attacks (F3a) flagged | {tpr} |",
            f"| all attacks flagged | {total} |",
            f"| benign corpus flagged (false positive) | {fpr} |",
            "",
            "> Layer 1 flags codepoint-level smuggling only. It is expected to flag the",
            "> F3a family and little else; F3b (hidden markup) needs a markup parser and",
            "> is a later increment. Measured against the corpus, not the scripted ASR.",
        ]
    )
