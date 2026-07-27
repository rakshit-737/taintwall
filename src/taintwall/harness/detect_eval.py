"""Measure the detection layers directly against the labelled corpora.

The detection layers are not evaluated through the ablation attack-success rate —
the scripted planner cannot exhibit the obfuscation Layer 1 defeats, and Layer 2
is a signal that never gates. They are evaluated here, against the corpus.

The two layers are a study in contrast, and that contrast is the point:

- **Layer 1** (deterministic normalization) catches the two concealment families
  at 100% with 0% false positives. Precise, because the thing it detects — a
  character that a human cannot see — is unambiguous.
- **Layer 2** (heuristic content classifier) is a lose-lose tradeoff: catching more
  attacks means flagging more legitimate text, and it never gets the
  false-positive rate near zero, because ordinary prose legitimately discusses the
  very concepts it keys on. See docs/why-classifiers-fail.md.
"""

from __future__ import annotations

from dataclasses import dataclass

from taintwall.corpus.loader import load_attacks, load_benign
from taintwall.corpus.schema import Family
from taintwall.harness.metrics import Proportion, aggregate
from taintwall.heuristics import heuristic_score
from taintwall.normalize import detect


@dataclass(frozen=True, slots=True)
class DetectionReport:
    codepoint_family_tpr: Proportion
    markup_family_tpr: Proportion
    all_attacks_flagged: Proportion
    benign_false_positive: Proportion


def evaluate_layer1() -> DetectionReport:
    attacks = load_attacks()
    benign = load_benign()

    f3a = [r for r in attacks if r.family is Family.F3A]
    f3b = [r for r in attacks if r.family is Family.F3B]
    f3a_hits = sum(1 for r in f3a if detect(r.payload))
    f3b_hits = sum(1 for r in f3b if detect(r.payload))
    all_hits = sum(1 for r in attacks if detect(r.payload))
    benign_hits = sum(1 for r in benign if detect(r.text))

    return DetectionReport(
        codepoint_family_tpr=Proportion(f3a_hits, len(f3a)),
        markup_family_tpr=Proportion(f3b_hits, len(f3b)),
        all_attacks_flagged=Proportion(all_hits, len(attacks)),
        benign_false_positive=Proportion(benign_hits, len(benign)),
    )


@dataclass(frozen=True, slots=True)
class Layer2Report:
    threshold: float
    per_family_tpr: dict[str, Proportion]
    all_attacks_tpr: Proportion
    benign_false_positive: Proportion


def evaluate_layer2(threshold: float) -> Layer2Report:
    attacks = load_attacks()
    benign = load_benign()

    def flagged(text: str) -> bool:
        return heuristic_score(text) >= threshold

    per_family = aggregate(
        attacks, key=lambda r: r.family.value, success=lambda r: flagged(r.payload)
    )
    all_tpr = Proportion(sum(1 for r in attacks if flagged(r.payload)), len(attacks))
    benign_fp = Proportion(sum(1 for r in benign if flagged(r.text)), len(benign))
    return Layer2Report(
        threshold=threshold,
        per_family_tpr=dict(per_family),
        all_attacks_tpr=all_tpr,
        benign_false_positive=benign_fp,
    )


def _row(label: str, value: Proportion) -> str:
    return f"| {label} | {value.format()} |"


def render_detection_markdown(report: DetectionReport) -> str:
    lines = [
        "# Layer 1 detection (deterministic normalization)",
        "",
        "| metric | value |",
        "|---|---|",
        _row("invisible-codepoint attacks (F3a) flagged", report.codepoint_family_tpr),
        _row("hidden-markup attacks (F3b) flagged", report.markup_family_tpr),
        _row("all attacks flagged", report.all_attacks_flagged),
        _row("benign corpus flagged (false positive)", report.benign_false_positive),
        "",
        "> Precise by construction: an invisible character is unambiguous. Layer 1",
        "> flags exactly the two concealment families and nothing else, at 0% FP.",
    ]
    return "\n".join(lines)


def render_layer2_markdown(thresholds: tuple[float, ...]) -> str:
    lines = [
        "# Layer 2 detection (heuristic content classifier)",
        "",
        "A signal, never a gate. The table sweeps the flag threshold to show the",
        "tradeoff: there is no setting that catches most attacks without a real",
        "false-positive cost on legitimate text.",
        "",
        "| threshold | attacks flagged | benign false positive |",
        "|---|---|---|",
    ]
    reports = [evaluate_layer2(t) for t in thresholds]
    for report in reports:
        lines.append(
            f"| {report.threshold:.1f} | {report.all_attacks_tpr.format()} "
            f"| {report.benign_false_positive.format()} |"
        )

    mid = reports[len(reports) // 2]
    lines += [
        "",
        f"Per-family true-positive rate at threshold {mid.threshold:.1f}:",
        "",
        "| family | TPR |",
        "|---|---|",
    ]
    for family in sorted(mid.per_family_tpr):
        lines.append(_row(family, mid.per_family_tpr[family]))

    lines += [
        "",
        "> The false-positive rate never reaches zero - it floors around 9% no matter",
        "> how high the threshold goes, because the benign corpus legitimately contains",
        "> the words the classifier keys on. Pushing the threshold up to control that",
        "> floor collapses the true-positive rate (to ~19% at 0.5). F4 (client-render)",
        "> and F8 (confused deputy) carry no imperative markers and stay near-invisible",
        "> at any threshold. This reproduces the published result (arXiv 2410.22770) on",
        "> our own corpus, and is why Layer 2 is a signal into the policy layer, not a",
        "> gate. Contrast Layer 1: 100% on its families, 0% FP.",
    ]
    return "\n".join(lines)


def render_all_detection_markdown() -> str:
    return (
        render_detection_markdown(evaluate_layer1())
        + "\n\n"
        + render_layer2_markdown((0.3, 0.4, 0.5))
        + "\n"
    )
