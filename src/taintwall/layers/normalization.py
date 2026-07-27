"""Layer 1: normalize tool output and detect codepoint-level smuggling.

This replaces the Phase 1 tag stub. On every tool result it strips the invisible
carrier characters that hide a directive from a human reviewer, so a real model
downstream never receives the smuggled instruction. It records what it found on
the result, but it does not itself block calls — Layer 1 is an output transform;
gating is the policy layer's job.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace

from taintwall.agent.fake_llm import Transcript
from taintwall.agent.tools import ToolCall, ToolResult
from taintwall.layers.base import Decision, Verdict
from taintwall.normalize import Finding, normalize


@dataclass(slots=True)
class NormalizationLayer:
    name: str = "L1-normalize"
    neutralize: bool = True
    findings_seen: list[frozenset[Finding]] = field(default_factory=list)

    def on_tool_output(self, result: ToolResult) -> ToolResult:
        outcome = normalize(result.content)
        self.findings_seen.append(outcome.findings)
        if self.neutralize and not outcome.is_clean:
            return replace(result, content=outcome.text)
        return result

    def on_tool_call(self, call: ToolCall, transcript: Transcript) -> Decision:
        return Decision(Verdict.ALLOW, f"{self.name}: output-transform only")
