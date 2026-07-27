"""The layer protocol and the stack that composes layers into one decision."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from taintwall.agent.fake_llm import Transcript
from taintwall.agent.tools import ToolCall, ToolResult


class Verdict(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    ASK = "ask"
    SANITIZE = "sanitize"


@dataclass(frozen=True, slots=True)
class Decision:
    verdict: Verdict
    reason: str
    score: float = 0.0


class Layer(Protocol):
    # Read-only so that frozen-dataclass layers (whose fields are read-only)
    # still structurally conform to the protocol.
    @property
    def name(self) -> str: ...

    def on_tool_output(self, result: ToolResult) -> ToolResult: ...

    def on_tool_call(self, call: ToolCall, transcript: Transcript) -> Decision: ...


# Deny beats ask beats sanitize beats allow, mirroring the Claude Agent SDK hook
# precedence: any single layer's deny wins.
_PRECEDENCE = (Verdict.DENY, Verdict.ASK, Verdict.SANITIZE, Verdict.ALLOW)


@dataclass(frozen=True, slots=True)
class LayerStack:
    label: str
    layers: tuple[Layer, ...]

    def apply_output(self, result: ToolResult) -> ToolResult:
        for layer in self.layers:
            result = layer.on_tool_output(result)
        return result

    def decide(self, call: ToolCall, transcript: Transcript) -> Decision:
        decisions = [layer.on_tool_call(call, transcript) for layer in self.layers]
        if not decisions:
            return Decision(Verdict.ALLOW, "no layers")
        for verdict in _PRECEDENCE:
            for decision in decisions:
                if decision.verdict is verdict:
                    return decision
        return Decision(Verdict.ALLOW, "no layers")
