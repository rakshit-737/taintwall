"""Generate a self-contained HTML dashboard from the live harness results.

No third-party dependencies and no external assets — inline SVG, inline CSS,
theme-aware (it follows the viewer's light/dark setting). The numbers are computed
from the harness on every render, so the page cannot drift from the code.

The visual story is the project's thesis: exfiltration is flat across the content
layers and collapses at the action and provenance layers.
"""

from __future__ import annotations

import html
from dataclasses import dataclass
from functools import lru_cache

from taintwall.corpus.loader import load_attacks
from taintwall.harness.detect_eval import evaluate_layer1, evaluate_layer2
from taintwall.harness.report import build_reports
from taintwall.harness.runner import ModelKind, run_matrix
from taintwall.layers.composition import ABLATION_LABELS
from taintwall.tasks.definitions import TASKS


@dataclass(frozen=True, slots=True)
class StackBar:
    label: str
    exfiltration: float  # 0..1
    utility: float  # 0..1


@dataclass(frozen=True, slots=True)
class ThresholdRow:
    threshold: float
    tpr: float
    fpr: float


@dataclass(frozen=True, slots=True)
class DashboardData:
    stacks: tuple[StackBar, ...]
    f3a_tpr: float
    f3b_tpr: float
    layer1_fpr: float
    thresholds: tuple[ThresholdRow, ...]
    attack_count: int
    task_count: int


@lru_cache(maxsize=1)
def gather_data() -> DashboardData:
    """Compute the dashboard's numbers from the harness. Cached — it is deterministic."""
    attacks = load_attacks()
    outcomes = run_matrix(
        tasks=TASKS,
        attacks=attacks,
        stack_labels=ABLATION_LABELS,
        model_kind=ModelKind.FAKE,
    )
    reports = {r.stack_label: r for r in build_reports(outcomes, model_kind=ModelKind.FAKE)}
    stacks = tuple(
        StackBar(
            label=label,
            exfiltration=reports[label].exfiltration.rate,
            utility=reports[label].utility_under_attack.rate,
        )
        for label in ABLATION_LABELS
    )

    l1 = evaluate_layer1()
    threshold_rows: list[ThresholdRow] = []
    for t in (0.3, 0.4, 0.5):
        l2 = evaluate_layer2(t)
        threshold_rows.append(
            ThresholdRow(
                threshold=t, tpr=l2.all_attacks_tpr.rate, fpr=l2.benign_false_positive.rate
            )
        )
    thresholds = tuple(threshold_rows)
    return DashboardData(
        stacks=stacks,
        f3a_tpr=l1.codepoint_family_tpr.rate,
        f3b_tpr=l1.markup_family_tpr.rate,
        layer1_fpr=l1.benign_false_positive.rate,
        thresholds=thresholds,
        attack_count=len(attacks),
        task_count=len(TASKS),
    )


# --- SVG helpers -----------------------------------------------------------

_W = 640
_PLOT_H = 260
_PAD_L = 48
_PAD_B = 56
_PAD_T = 16


def _pct(x: float) -> str:
    return f"{x * 100:.0f}%" if x in (0.0, 1.0) else f"{x * 100:.1f}%"


def _exfil_chart(stacks: tuple[StackBar, ...]) -> str:
    n = len(stacks)
    plot_w = _W - _PAD_L - 16
    slot = plot_w / n
    bar_w = slot * 0.5
    base_y = _PAD_T + _PLOT_H
    parts: list[str] = []

    # recessive gridlines at 0/25/50/75/100 (scale is 0..0.5 since max ~44%)
    max_v = 0.5
    for g in (0.0, 0.125, 0.25, 0.375, 0.5):
        y = base_y - (g / max_v) * _PLOT_H
        parts.append(
            f'<line x1="{_PAD_L}" y1="{y:.1f}" x2="{_W - 16}" y2="{y:.1f}" '
            f'class="grid"/>'
            f'<text x="{_PAD_L - 8}" y="{y + 4:.1f}" class="tick" text-anchor="end">'
            f"{g * 100:.0f}%</text>"
        )

    for i, s in enumerate(stacks):
        x = _PAD_L + slot * i + (slot - bar_w) / 2
        h = (s.exfiltration / max_v) * _PLOT_H
        y = base_y - h
        is_zero = s.exfiltration <= 0.001
        klass = "bar-good" if s.exfiltration <= 0.02 else "bar"
        # a visible stub even at 0 so the category reads
        draw_h = max(h, 2.0)
        draw_y = base_y - draw_h
        parts.append(
            f'<rect x="{x:.1f}" y="{draw_y:.1f}" width="{bar_w:.1f}" height="{draw_h:.1f}" '
            f'rx="4" class="{klass}"><title>{html.escape(s.label)}: '
            f"exfiltration {_pct(s.exfiltration)}, utility {_pct(s.utility)}</title></rect>"
        )
        label = _pct(s.exfiltration)
        parts.append(
            f'<text x="{x + bar_w / 2:.1f}" y="{draw_y - 6:.1f}" class="val" '
            f'text-anchor="middle">{label}{" ✓" if is_zero else ""}</text>'
        )
        parts.append(
            f'<text x="{x + bar_w / 2:.1f}" y="{base_y + 18:.1f}" class="cat" '
            f'text-anchor="middle">{html.escape(s.label)}</text>'
        )

    return (
        f'<svg viewBox="0 0 {_W} {_PLOT_H + _PAD_T + _PAD_B}" role="img" '
        f'aria-label="Exfiltration rate by defense stack" class="chart">'
        f'<line x1="{_PAD_L}" y1="{base_y}" x2="{_W - 16}" y2="{base_y}" class="axis"/>'
        + "".join(parts)
        + "</svg>"
    )


def _tradeoff_chart(rows: tuple[ThresholdRow, ...]) -> str:
    n = len(rows)
    plot_w = _W - _PAD_L - 16
    slot = plot_w / n
    group_w = slot * 0.6
    bar_w = group_w / 2
    base_y = _PAD_T + _PLOT_H
    parts: list[str] = []

    for g in (0.0, 0.25, 0.5, 0.75, 1.0):
        y = base_y - g * _PLOT_H
        parts.append(
            f'<line x1="{_PAD_L}" y1="{y:.1f}" x2="{_W - 16}" y2="{y:.1f}" class="grid"/>'
            f'<text x="{_PAD_L - 8}" y="{y + 4:.1f}" class="tick" text-anchor="end">'
            f"{g * 100:.0f}%</text>"
        )

    for i, r in enumerate(rows):
        gx = _PAD_L + slot * i + (slot - group_w) / 2
        for j, (val, klass, name) in enumerate(
            ((r.tpr, "bar", "attacks flagged"), (r.fpr, "bar-warn", "benign false positive"))
        ):
            x = gx + bar_w * j
            h = max(val * _PLOT_H, 2.0)
            y = base_y - h
            parts.append(
                f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_w - 2:.1f}" height="{h:.1f}" '
                f'rx="4" class="{klass}"><title>threshold {r.threshold:.1f} - '
                f"{name} {_pct(val)}</title></rect>"
            )
        parts.append(
            f'<text x="{gx + group_w / 2:.1f}" y="{base_y + 18:.1f}" class="cat" '
            f'text-anchor="middle">thr {r.threshold:.1f}</text>'
        )

    return (
        f'<svg viewBox="0 0 {_W} {_PLOT_H + _PAD_T + _PAD_B}" role="img" '
        f'aria-label="Layer 2 true-positive vs false-positive by threshold" class="chart">'
        f'<line x1="{_PAD_L}" y1="{base_y}" x2="{_W - 16}" y2="{base_y}" class="axis"/>'
        + "".join(parts)
        + "</svg>"
    )


def _tile(value: str, label: str, good: bool = False) -> str:
    cls = "tile tile-good" if good else "tile"
    return (
        f'<div class="{cls}"><div class="tile-val">{html.escape(value)}</div>'
        f'<div class="tile-label">{html.escape(label)}</div></div>'
    )


def _table(data: DashboardData) -> str:
    rows = "".join(
        f"<tr><td>{html.escape(s.label)}</td><td>{_pct(s.utility)}</td>"
        f"<td>{_pct(s.exfiltration)}</td></tr>"
        for s in data.stacks
    )
    return (
        '<table class="data-table"><caption>Ablation (deterministic track, '
        f"{data.task_count} tasks x {data.attack_count} attacks)</caption>"
        "<thead><tr><th>stack</th><th>utility under attack</th>"
        "<th>exfiltration</th></tr></thead><tbody>" + rows + "</tbody></table>"
    )


_CSS = """
:root { color-scheme: light dark; }
.viz-root {
  --page: #f9f9f7; --surface: #fcfcfb; --ink: #0b0b0b; --ink2: #52514e;
  --muted: #898781; --grid: #e1e0d9; --axis: #c3c2b7;
  --series-1: #2a78d6; --series-2: #eb6834; --good: #0ca30c;
  --border: rgba(11,11,11,0.10);
}
@media (prefers-color-scheme: dark) {
  :root:where(:not([data-theme="light"])) .viz-root {
    --page: #0d0d0d; --surface: #1a1a19; --ink: #fff; --ink2: #c3c2b7;
    --muted: #898781; --grid: #2c2c2a; --axis: #383835;
    --series-1: #3987e5; --series-2: #d95926; --good: #0ca30c;
    --border: rgba(255,255,255,0.10);
  }
}
:root[data-theme="dark"] .viz-root {
  --page: #0d0d0d; --surface: #1a1a19; --ink: #fff; --ink2: #c3c2b7;
  --muted: #898781; --grid: #2c2c2a; --axis: #383835;
  --series-1: #3987e5; --series-2: #d95926; --good: #0ca30c;
  --border: rgba(255,255,255,0.10);
}
.viz-root {
  font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
  background: var(--page); color: var(--ink);
  margin: 0; padding: 32px; line-height: 1.5;
}
.wrap { max-width: 760px; margin: 0 auto; }
h1 { font-size: 1.5rem; margin: 0 0 4px; }
h2 { font-size: 1.05rem; margin: 32px 0 4px; }
.lede { color: var(--ink2); margin: 0 0 8px; }
.card {
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 12px; padding: 20px; margin-top: 12px; overflow-x: auto;
}
.chart { width: 100%; height: auto; max-width: 100%; }
.grid { stroke: var(--grid); stroke-width: 1; }
.axis { stroke: var(--axis); stroke-width: 1; }
.bar { fill: var(--series-1); }
.bar-warn { fill: var(--series-2); }
.bar-good { fill: var(--good); }
.val { fill: var(--ink); font-size: 12px; font-weight: 600; }
.cat { fill: var(--ink2); font-size: 12px; }
.tick { fill: var(--muted); font-size: 11px; font-variant-numeric: tabular-nums; }
.tiles { display: flex; gap: 12px; flex-wrap: wrap; margin-top: 12px; }
.tile {
  flex: 1 1 140px; background: var(--surface); border: 1px solid var(--border);
  border-radius: 12px; padding: 16px;
}
.tile-good { border-color: var(--good); }
.tile-val { font-size: 1.8rem; font-weight: 700; }
.tile-label { color: var(--ink2); font-size: 0.85rem; margin-top: 2px; }
.legend { display: flex; gap: 16px; font-size: 0.85rem; color: var(--ink2); margin-top: 8px; }
.swatch {
  display: inline-block; width: 12px; height: 12px;
  border-radius: 3px; vertical-align: middle; margin-right: 6px;
}
.data-table { border-collapse: collapse; width: 100%; margin-top: 12px; font-size: 0.85rem; }
.data-table caption { text-align: left; color: var(--muted); padding-bottom: 6px; }
.data-table th, .data-table td {
  text-align: left; padding: 6px 10px;
  border-bottom: 1px solid var(--border); font-variant-numeric: tabular-nums;
}
.foot { color: var(--muted); font-size: 0.8rem; margin-top: 32px; }
"""


def render_dashboard(data: DashboardData) -> str:
    sw1 = '<span class="swatch" style="background:var(--series-1)"></span>'
    sw2 = '<span class="swatch" style="background:var(--series-2)"></span>'
    legend = (
        '<div class="legend">'
        f"<span>{sw1}attacks flagged (TPR)</span>"
        f"<span>{sw2}benign false positive (FPR)</span>"
        "</div>"
    )
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>taintwall — measured defense</title>
<style>{_CSS}</style>
</head>
<body class="viz-root">
<div class="wrap">
  <h1>taintwall</h1>
  <p class="lede">An in-process prompt-injection firewall for AI agents. Every number here
  is computed from the harness, over {data.task_count} benign tasks and
  {data.attack_count} labelled attacks.</p>

  <h2>The thesis, measured</h2>
  <p class="lede">Content inspection does not reduce exfiltration. The action layer (intent
  policy) and the provenance layer do — to zero — while utility stays at 100%.</p>
  <div class="card">{_exfil_chart(data.stacks)}</div>
  {_table(data)}

  <h2>Layer 1 — deterministic detection</h2>
  <p class="lede">Precise by construction: an invisible character is unambiguous.</p>
  <div class="tiles">
    {_tile(_pct(data.f3a_tpr), "invisible codepoints (F3a) caught", good=data.f3a_tpr >= 0.999)}
    {_tile(_pct(data.f3b_tpr), "hidden markup (F3b) caught", good=data.f3b_tpr >= 0.999)}
    {_tile(_pct(data.layer1_fpr), "benign false positives", good=data.layer1_fpr <= 0.001)}
  </div>

  <h2>Layer 2 — the classifier tradeoff</h2>
  <p class="lede">A signal, never a gate. There is no threshold that catches most attacks
  without a real false-positive cost — the false-positive rate never reaches zero.</p>
  <div class="card">{_tradeoff_chart(data.thresholds)}{legend}</div>

  <p class="foot">Generated by <code>taintwall dashboard</code>. Deterministic (scripted)
  track: exfiltration counts sink calls that executed; read the delta across stacks.
  Attack-success rate against a real model is out of scope for this track by design.</p>
</div>
</body>
</html>
"""
