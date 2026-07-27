"""Stack composition, plus constant-returning placeholders for layers 2-4.

Layer 1 is real as of Phase 2 (`NormalizationLayer`); layers 2-4 are still
stubs that pass output through unchanged and allow every call. Replacing a stub
with a working layer is the entire content of a later increment; nothing
downstream of `build_stack` needs to change.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from taintwall.agent.fake_llm import Transcript
from taintwall.agent.tools import ToolCall, ToolResult
from taintwall.layers.base import Decision, Layer, LayerStack, Verdict
from taintwall.layers.normalization import NormalizationLayer
from taintwall.layers.policy import PolicyLayer, SessionIntent


@dataclass(frozen=True, slots=True)
class _Stub:
    name: str

    def on_tool_output(self, result: ToolResult) -> ToolResult:
        return result

    def on_tool_call(self, call: ToolCall, transcript: Transcript) -> Decision:
        return Decision(Verdict.ALLOW, f"{self.name}: stub")


def tag_layer() -> Layer:
    """Layer 1: normalization + codepoint-smuggling detection (Phase 2)."""
    return NormalizationLayer()


def detect_stub() -> Layer:
    """Layer 2 placeholder. Phase 2 wraps a public detector and emits a score."""
    return _Stub("L2-detect")


def canary_stub() -> Layer:
    """Layer 4 placeholder. Phase 2 plants and watches for canary tokens."""
    return _Stub("L4-canary")


ABLATION_LABELS: tuple[str, ...] = ("none", "+L1", "+L1L2", "+L1L2L3", "+all")


def build_stack(label: str, intent: SessionIntent | None = None) -> LayerStack:
    """Compose a layer stack. `intent` configures Layer 3; defaults to read-only.

    The `none`, `+L1`, and `+L1L2` stacks ignore intent (they contain no policy
    layer). `+L1L2L3` and `+all` gate tool calls against it.
    """
    session_intent = intent if intent is not None else SessionIntent.read_only()

    def policy_layer() -> Layer:
        return PolicyLayer(session_intent)

    factories: dict[str, tuple[Callable[[], Layer], ...]] = {
        "none": (),
        "+L1": (tag_layer,),
        "+L1L2": (tag_layer, detect_stub),
        "+L1L2L3": (tag_layer, detect_stub, policy_layer),
        "+all": (tag_layer, detect_stub, policy_layer, canary_stub),
    }
    return LayerStack(label=label, layers=tuple(factory() for factory in factories[label]))
