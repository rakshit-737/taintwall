"""Layer 2: a heuristic injection-likelihood signal.

This layer computes a score on tool output and records it. It never gates a call
on its own — that is the deliberate design position from the Phase 1 research: a
content classifier for prompt injection is evadable and carries a real
false-positive cost, so it is one input to the policy layer, not a decision.

Its score would, in a fuller build, feed the policy layer's decision. Here it is
recorded and measured; see docs/why-classifiers-fail.md for what it catches and
what it costs.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from taintwall.agent.fake_llm import Transcript
from taintwall.agent.tools import ToolCall, ToolResult
from taintwall.heuristics import heuristic_score
from taintwall.layers.base import Decision, Verdict


@dataclass(slots=True)
class DetectLayer:
    threshold: float = 0.4
    name: str = "L2-detect"
    scores_seen: list[float] = field(default_factory=list)

    def on_tool_output(self, result: ToolResult) -> ToolResult:
        self.scores_seen.append(heuristic_score(result.content))
        return result

    def on_tool_call(self, call: ToolCall, transcript: Transcript) -> Decision:
        # A signal, never a gate. It always allows; its value is the recorded
        # score, not a decision.
        return Decision(Verdict.ALLOW, f"{self.name}: signal only", score=0.0)
