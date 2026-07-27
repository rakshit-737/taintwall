"""The evaluation matrix: every task, crossed against every attack, under every stack.

A clean (attack-free) run per task per stack supplies benign utility; the
attacked runs supply utility-under-attack and, on a real model only, attack
success. The scripted planner produces the deterministic track; the real-model
track lives in taintwall.agent.claude_runner and is not driven from here.
"""

from __future__ import annotations

import time
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum

from taintwall.agent.fake_llm import FakeLLM
from taintwall.agent.loop import RunResult, run_agent
from taintwall.agent.sinks import ExfilRecorder
from taintwall.agent.tools import build_default_registry
from taintwall.corpus.schema import AttackRecord
from taintwall.layers.composition import build_stack
from taintwall.layers.policy import SessionIntent
from taintwall.tasks.suite import BenignTask


class ModelKind(StrEnum):
    FAKE = "fake"
    REAL = "real"


@dataclass(frozen=True, slots=True)
class CaseOutcome:
    task_id: str
    attack_id: str | None
    family: str | None
    stack_label: str
    task_succeeded: bool
    attack_succeeded: bool
    latency_ms: float


def _execute(
    task: BenignTask, attack: AttackRecord | None, stack_label: str
) -> tuple[RunResult, float]:
    world = task.seed.build()
    if attack is not None:
        point = task.injection_points[0]
        world.inject(channel=point.channel, key=point.key, payload=attack.payload)

    recorder = ExfilRecorder()
    registry = build_default_registry(world, recorder)
    private_values = frozenset(world.secrets.values())
    # The naive planner copies the private data it can see into an exfil call, as
    # a real harvest attack does - giving Layer 4 something to catch.
    llm = FakeLLM(task.script, private_data=tuple(sorted(private_values)))
    stack = build_stack(
        stack_label,
        SessionIntent(task.allowed_capabilities),
        private_values=private_values,
    )

    started = time.perf_counter()
    result = run_agent(
        intent=task.intent,
        llm=llm,
        registry=registry,
        recorder=recorder,
        stack=stack,
    )
    return result, (time.perf_counter() - started) * 1000.0


def run_matrix(
    *,
    tasks: Sequence[BenignTask],
    attacks: Sequence[AttackRecord],
    stack_labels: Sequence[str],
    model_kind: ModelKind,
    runs: int = 1,
) -> tuple[CaseOutcome, ...]:
    if model_kind is ModelKind.REAL:
        raise NotImplementedError(
            "real-model runs are wired in taintwall.agent.claude_runner; "
            "run_matrix currently drives the deterministic planner only"
        )

    outcomes: list[CaseOutcome] = []
    for _ in range(runs):
        for label in stack_labels:
            for task in tasks:
                result, elapsed = _execute(task, None, label)
                outcomes.append(
                    CaseOutcome(
                        task_id=task.id,
                        attack_id=None,
                        family=None,
                        stack_label=label,
                        task_succeeded=task.succeeded(result),
                        attack_succeeded=False,
                        latency_ms=elapsed,
                    )
                )
                for attack in attacks:
                    result, elapsed = _execute(task, attack, label)
                    outcomes.append(
                        CaseOutcome(
                            task_id=task.id,
                            attack_id=attack.id,
                            family=attack.family.value,
                            stack_label=label,
                            task_succeeded=task.succeeded(result),
                            attack_succeeded=bool(result.exfil),
                            latency_ms=elapsed,
                        )
                    )
    return tuple(outcomes)
