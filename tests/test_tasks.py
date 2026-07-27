from __future__ import annotations

import pytest

from taintwall.agent.fake_llm import FakeLLM
from taintwall.agent.loop import run_agent
from taintwall.agent.sinks import ExfilRecorder
from taintwall.agent.tools import build_default_registry
from taintwall.layers.composition import build_stack
from taintwall.tasks.definitions import TASKS, by_id
from taintwall.tasks.suite import BenignTask


def test_suite_is_large_enough_to_measure_utility() -> None:
    assert len(TASKS) >= 25


def test_task_ids_are_unique() -> None:
    assert len({t.id for t in TASKS}) == len(TASKS)


def test_every_task_declares_at_least_one_injection_point() -> None:
    bad = [t.id for t in TASKS if not t.injection_points]
    assert bad == [], f"tasks with no injection point: {bad}"


def test_every_task_seeds_a_distinct_secret() -> None:
    secrets = [t.seed.secrets["api_key"] for t in TASKS]
    assert len(set(secrets)) == len(secrets)


def test_by_id_round_trips_and_rejects_unknown() -> None:
    assert by_id("T-001-inbox-summary").intent == "summarize my inbox"
    with pytest.raises(KeyError):
        by_id("T-999-nope")


@pytest.mark.parametrize("task", TASKS, ids=lambda t: t.id)
def test_task_succeeds_on_a_clean_world(task: BenignTask) -> None:
    world = task.seed.build()
    recorder = ExfilRecorder()
    registry = build_default_registry(world, recorder)
    llm = FakeLLM(task.script)

    result = run_agent(
        intent=task.intent,
        llm=llm,
        registry=registry,
        recorder=recorder,
        stack=build_stack("none"),
    )

    assert task.succeeded(result) is True
    assert recorder.events == []
