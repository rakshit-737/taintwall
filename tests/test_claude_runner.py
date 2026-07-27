from __future__ import annotations

import pytest

from taintwall.agent.claude_runner import build_sdk_tools, sdk_available
from taintwall.agent.sinks import ExfilRecorder
from taintwall.agent.tools import build_default_registry
from taintwall.agent.world import World


def test_sdk_available_is_a_bool_and_never_raises() -> None:
    assert isinstance(sdk_available(), bool)


@pytest.mark.skipif(not sdk_available(), reason="claude-agent-sdk not installed")
def test_every_registry_tool_is_exposed_to_the_sdk() -> None:
    registry = build_default_registry(World.seeded(), ExfilRecorder())
    assert len(build_sdk_tools(registry)) == len(registry.names())


@pytest.mark.live
def test_real_model_run_reads_the_seeded_email() -> None:
    from taintwall.agent.claude_runner import run_with_claude

    world = World.seeded(emails={"1": "Q3 revenue is up 4 percent."})
    recorder = ExfilRecorder()
    registry = build_default_registry(world, recorder)

    result = run_with_claude(intent="summarize email 1", registry=registry, recorder=recorder)

    assert any(call.name == "read_email" for call in result.tool_calls)
