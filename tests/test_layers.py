from __future__ import annotations

from dataclasses import dataclass

import pytest

from taintwall.agent.fake_llm import Transcript
from taintwall.agent.tools import ToolCall, ToolResult
from taintwall.layers.base import Decision, LayerStack, Verdict
from taintwall.layers.stubs import ABLATION_LABELS, build_stack


@dataclass(frozen=True, slots=True)
class _FixedLayer:
    """A one-verdict layer, used to test stack precedence."""

    name: str
    verdict: Verdict

    def on_tool_output(self, result: ToolResult) -> ToolResult:
        return result

    def on_tool_call(self, call: ToolCall, transcript: Transcript) -> Decision:
        return Decision(self.verdict, f"{self.name}: fixed")


def test_all_five_ablation_columns_exist() -> None:
    assert ABLATION_LABELS == ("none", "+L1", "+L1L2", "+L1L2L3", "+all")


@pytest.mark.parametrize("label", ["none", "+L1", "+L1L2"])
def test_stacks_without_a_policy_layer_allow_a_sink_call(label: str) -> None:
    stack = build_stack(label)
    decision = stack.decide(ToolCall("send_email", {"to": "x@example.invalid"}), Transcript("t"))
    assert decision.verdict is Verdict.ALLOW


@pytest.mark.parametrize("label", ["+L1L2L3", "+all"])
def test_policy_stacks_deny_a_sink_call_in_a_read_only_session(label: str) -> None:
    stack = build_stack(label)  # default intent is read-only
    decision = stack.decide(ToolCall("send_email", {"to": "x@example.invalid"}), Transcript("t"))
    assert decision.verdict is Verdict.DENY


@pytest.mark.parametrize("label", ABLATION_LABELS)
def test_every_stack_allows_a_read_call(label: str) -> None:
    stack = build_stack(label)
    decision = stack.decide(ToolCall("read_email", {"id": "1"}), Transcript("t"))
    assert decision.verdict is Verdict.ALLOW


@pytest.mark.parametrize("label", ABLATION_LABELS)
def test_every_stub_stack_passes_output_through_unchanged(label: str) -> None:
    stack = build_stack(label)
    result = ToolResult(ToolCall("read_email", {"id": "1"}), "body text")
    assert stack.apply_output(result).content == "body text"


def test_stack_layer_counts_increase_monotonically() -> None:
    counts = [len(build_stack(label).layers) for label in ABLATION_LABELS]
    assert counts == sorted(counts)
    assert counts[0] == 0
    assert counts[-1] == 4


def test_unknown_label_is_rejected() -> None:
    with pytest.raises(KeyError):
        build_stack("+L9")


def test_deny_wins_over_allow_in_a_mixed_stack() -> None:
    stack = LayerStack(
        label="mixed",
        layers=(
            _FixedLayer("allow", Verdict.ALLOW),
            _FixedLayer("deny", Verdict.DENY),
        ),
    )
    decision = stack.decide(ToolCall("http_post", {"url": "x"}), Transcript("t"))
    assert decision.verdict is Verdict.DENY
    assert decision.reason == "deny: fixed"
