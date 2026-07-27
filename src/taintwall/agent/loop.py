"""The agent loop: plan, gate each call through the layer stack, execute, repeat."""

from __future__ import annotations

from dataclasses import dataclass

from taintwall.agent.fake_llm import FakeLLM, Transcript
from taintwall.agent.sinks import ExfilEvent, ExfilRecorder
from taintwall.agent.tools import ToolCall, ToolRegistry
from taintwall.layers.base import LayerStack, Verdict


@dataclass(frozen=True, slots=True)
class RunResult:
    transcript: Transcript
    exfil: tuple[ExfilEvent, ...]
    tool_calls: tuple[ToolCall, ...]
    blocked_calls: tuple[ToolCall, ...]
    final_text: str


def run_agent(
    *,
    intent: str,
    llm: FakeLLM,
    registry: ToolRegistry,
    recorder: ExfilRecorder,
    stack: LayerStack,
    max_steps: int = 8,
) -> RunResult:
    """Drive the demo agent until it stops calling tools or hits max_steps.

    Each planned call is gated: a DENY verdict blocks it and records it as
    blocked; anything else executes, and the result passes through the stack's
    output layers before it re-enters the transcript.
    """
    transcript = Transcript(intent=intent)
    executed: list[ToolCall] = []
    blocked: list[ToolCall] = []
    final_text = ""

    for _ in range(max_steps):
        plan = llm.next(transcript)
        if plan.text:
            final_text = plan.text
            transcript.texts.append(plan.text)
        if not plan.tool_calls:
            break

        for call in plan.tool_calls:
            decision = stack.decide(call, transcript)
            if decision.verdict is Verdict.DENY:
                blocked.append(call)
                continue
            result = stack.apply_output(registry.call(call))
            executed.append(call)
            transcript.results.append(result)

    return RunResult(
        transcript=transcript,
        exfil=tuple(recorder.events),
        tool_calls=tuple(executed),
        blocked_calls=tuple(blocked),
        final_text=final_text,
    )
