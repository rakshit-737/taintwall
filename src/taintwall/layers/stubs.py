"""Constant-returning placeholders for layers 1-4.

Each stub is a real Layer that passes output through unchanged and allows every
call. Replacing a stub with a working layer is the entire content of a later
phase; nothing downstream of these functions needs to change.
"""

from __future__ import annotations

from dataclasses import dataclass

from taintwall.agent.fake_llm import Transcript
from taintwall.agent.tools import ToolCall, ToolResult
from taintwall.layers.base import Decision, Layer, LayerStack, Verdict


@dataclass(frozen=True, slots=True)
class _Stub:
    name: str

    def on_tool_output(self, result: ToolResult) -> ToolResult:
        return result

    def on_tool_call(self, call: ToolCall, transcript: Transcript) -> Decision:
        return Decision(Verdict.ALLOW, f"{self.name}: stub")


def tag_stub() -> Layer:
    """Layer 1 placeholder. Phase 2 replaces this with Tainted[T] tagging."""
    return _Stub("L1-tag")


def detect_stub() -> Layer:
    """Layer 2 placeholder. Phase 2 wraps a public detector and emits a score."""
    return _Stub("L2-detect")


def policy_stub() -> Layer:
    """Layer 3 placeholder. Phase 3 gates tool calls on declared session intent."""
    return _Stub("L3-policy")


def canary_stub() -> Layer:
    """Layer 4 placeholder. Phase 2 plants and watches for canary tokens."""
    return _Stub("L4-canary")


ABLATION_LABELS: tuple[str, ...] = ("none", "+L1", "+L1L2", "+L1L2L3", "+all")


def build_stack(label: str) -> LayerStack:
    factories = {
        "none": (),
        "+L1": (tag_stub,),
        "+L1L2": (tag_stub, detect_stub),
        "+L1L2L3": (tag_stub, detect_stub, policy_stub),
        "+all": (tag_stub, detect_stub, policy_stub, canary_stub),
    }[label]
    return LayerStack(label=label, layers=tuple(factory() for factory in factories))
