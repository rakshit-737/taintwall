"""The markdown reporter, and the guardrail that keeps a scripted ASR unprintable.

The reporter refuses to render an attack-success rate under the scripted planner.
That refusal is enforced here, in code, not left to a docs note: any number the
reporter *can* render will eventually be published, and a scripted planner's
compliance is authored, not observed.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from statistics import quantiles

from taintwall.harness.metrics import Proportion, aggregate
from taintwall.harness.runner import CaseOutcome, ModelKind

ASR_UNAVAILABLE = "N/A (scripted)"


@dataclass(frozen=True, slots=True)
class CellReport:
    stack_label: str
    benign_utility: Proportion
    utility_under_attack: Proportion
    asr: Proportion | None
    exfiltration: Proportion
    per_family_asr: Mapping[str, Proportion | None]
    latency_p50_ms: float
    latency_p95_ms: float


def _percentiles(values: Sequence[float]) -> tuple[float, float]:
    if not values:
        return (0.0, 0.0)
    if len(values) == 1:
        return (values[0], values[0])
    cuts = quantiles(values, n=100, method="inclusive")
    return (cuts[49], cuts[94])


def build_reports(
    outcomes: Sequence[CaseOutcome], *, model_kind: ModelKind
) -> tuple[CellReport, ...]:
    reports: list[CellReport] = []
    for label in dict.fromkeys(o.stack_label for o in outcomes):
        rows = [o for o in outcomes if o.stack_label == label]
        clean = [o for o in rows if o.attack_id is None]
        attacked = [o for o in rows if o.attack_id is not None]

        asr: Proportion | None
        per_family: dict[str, Proportion | None]
        if model_kind is ModelKind.FAKE:
            asr = None
            per_family = {o.family: None for o in attacked if o.family}
        else:
            asr = Proportion(sum(o.attack_succeeded for o in attacked), len(attacked))
            per_family = dict(
                aggregate(
                    [o for o in attacked if o.family],
                    key=lambda o: o.family or "",
                    success=lambda o: o.attack_succeeded,
                )
            )

        p50, p95 = _percentiles([o.latency_ms for o in rows])
        reports.append(
            CellReport(
                stack_label=label,
                benign_utility=Proportion(sum(o.task_succeeded for o in clean), len(clean)),
                utility_under_attack=Proportion(
                    sum(o.task_succeeded for o in attacked), len(attacked)
                ),
                asr=asr,
                exfiltration=Proportion(sum(o.attack_succeeded for o in attacked), len(attacked)),
                per_family_asr=per_family,
                latency_p50_ms=p50,
                latency_p95_ms=p95,
            )
        )
    return tuple(reports)


def render_markdown(
    reports: Sequence[CellReport], *, model_kind: ModelKind, fpr: Proportion | None = None
) -> str:
    if model_kind is ModelKind.FAKE and any(r.asr is not None for r in reports):
        raise ValueError(
            "refusing to render an attack-success rate from a scripted planner: "
            "the compliance is authored, not observed"
        )

    lines = [
        f"# taintwall ablation ({model_kind.value} model)",
        "",
        "| stack | benign utility | utility under attack | ASR | exfiltration | p50 ms | p95 ms |",
        "|---|---|---|---|---|---|---|",
    ]
    for report in reports:
        asr_cell = ASR_UNAVAILABLE if report.asr is None else report.asr.format()
        lines.append(
            f"| `{report.stack_label}` | {report.benign_utility.format()} "
            f"| {report.utility_under_attack.format()} | {asr_cell} "
            f"| {report.exfiltration.format()} "
            f"| {report.latency_p50_ms:.2f} | {report.latency_p95_ms:.2f} |"
        )

    lines += [
        "",
        "## Per-family attack success rate",
        "",
        "| stack | family | ASR |",
        "|---|---|---|",
    ]
    for report in reports:
        for family in sorted(report.per_family_asr):
            value = report.per_family_asr[family]
            cell = ASR_UNAVAILABLE if value is None else value.format()
            lines.append(f"| `{report.stack_label}` | {family} | {cell} |")

    if fpr is not None:
        lines += ["", f"**False-positive rate on the benign corpus:** {fpr.format()}"]

    lines += [
        "",
        "> Every cell reports its sample size and a 95% Wilson interval. A near-zero",
        "> attack-success rate is a statement about the benchmark, not about the",
        "> problem being solved - see arXiv 2510.05244.",
        ">",
        "> ASR (did a model obey) is N/A on the scripted track. Exfiltration counts",
        "> sink calls that actually executed; on the scripted track whether an attack",
        "> fires is authored, so read the *delta* across stacks - the drop from `none`",
        "> to `+L1L2L3` is Layer 3 blocking sink calls a read-only session should never",
        "> make - not the absolute value.",
    ]
    return "\n".join(lines) + "\n"
