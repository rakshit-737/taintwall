"""The taintwall command line: bench, corpus validate, corpus export."""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from taintwall.corpus.loader import load_attacks, load_benign
from taintwall.harness.detect_eval import evaluate_layer1, render_detection_markdown
from taintwall.harness.report import build_reports, render_markdown
from taintwall.harness.runner import ModelKind, run_matrix
from taintwall.layers.stubs import ABLATION_LABELS
from taintwall.tasks.definitions import TASKS


def _cmd_detect() -> int:
    sys.stdout.write(render_detection_markdown(evaluate_layer1()) + "\n")
    return 0


def _cmd_corpus_validate() -> int:
    attacks = load_attacks()
    benign = load_benign()
    families = sorted({r.family.value for r in attacks})
    print(f"{len(attacks)} attack records across {len(families)} buckets: {families}")
    print(f"{len(benign)} benign records")
    return 0


def _cmd_corpus_export(out: Path) -> int:
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8", newline="\n") as handle:
        for record in load_attacks():
            handle.write(json.dumps(dataclasses.asdict(record), ensure_ascii=True) + "\n")
    print(f"wrote {out}")
    return 0


def _cmd_bench(
    update_baseline: bool, model: str, limit_attacks: int | None, out: Path | None
) -> int:
    if update_baseline:
        from taintwall.harness.baseline import current_outcomes, write_baseline

        baseline_outcomes = current_outcomes()
        write_baseline(baseline_outcomes)
        print(f"baseline updated: {len(baseline_outcomes)} records")
        return 0

    if model == "real" and os.environ.get("TAINTWALL_DEMO_ACK") != "1":
        print(
            "real-model runs execute a deliberately vulnerable agent. "
            "Set TAINTWALL_DEMO_ACK=1 to acknowledge.",
            file=sys.stderr,
        )
        return 2

    attacks = load_attacks()
    if limit_attacks is not None:
        attacks = attacks[:limit_attacks]

    kind = ModelKind(model)
    outcomes = run_matrix(
        tasks=TASKS, attacks=attacks, stack_labels=ABLATION_LABELS, model_kind=kind
    )
    text = render_markdown(build_reports(outcomes, model_kind=kind), model_kind=kind)
    if out is not None:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8", newline="\n")
        print(f"wrote {out}")
    else:
        sys.stdout.write(text)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="taintwall")
    sub = parser.add_subparsers(dest="command", required=True)

    bench = sub.add_parser("bench", help="run the ablation matrix")
    bench.add_argument("--model", choices=["fake", "real"], default="fake")
    bench.add_argument("--limit-attacks", type=int, default=None)
    bench.add_argument("--out", type=Path, default=None)
    bench.add_argument("--update-baseline", action="store_true")

    sub.add_parser("detect", help="Layer 1 detection efficacy over the corpus")

    corpus = sub.add_parser("corpus", help="corpus utilities")
    corpus_sub = corpus.add_subparsers(dest="corpus_command", required=True)
    corpus_sub.add_parser("validate")
    export = corpus_sub.add_parser("export")
    export.add_argument("--out", type=Path, default=Path("corpus/attacks.jsonl"))

    args = parser.parse_args(argv)
    if args.command == "bench":
        return _cmd_bench(args.update_baseline, args.model, args.limit_attacks, args.out)
    if args.command == "detect":
        return _cmd_detect()
    if args.corpus_command == "validate":
        return _cmd_corpus_validate()
    return _cmd_corpus_export(args.out)


if __name__ == "__main__":
    raise SystemExit(main())
