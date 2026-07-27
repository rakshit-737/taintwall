"""Layer 4: deny a sink call that carries private data in its arguments.

This is the argument-level check that closes the KB-005 gap Layer 3 leaves open.
Layer 3 asks whether the session may reach a sink at all; Layer 4 asks whether
*this* sink call is carrying private data out. A session that legitimately holds
`send_email` still cannot use it to send a secret to an attacker.

A canary token is just a planted private value, so this is also the canary layer:
give it the session's private values (secrets and any planted canaries) and it
denies any sink call whose arguments contain one, verbatim or simply encoded.
"""

from __future__ import annotations

from dataclasses import dataclass

from taintwall.agent.fake_llm import Transcript
from taintwall.agent.tools import SINK_TOOLS, ToolCall, ToolResult
from taintwall.layers.base import Decision, Verdict
from taintwall.provenance import contains_private


@dataclass(frozen=True, slots=True)
class ProvenanceLayer:
    private_values: frozenset[str]
    name: str = "L4-provenance"

    def on_tool_output(self, result: ToolResult) -> ToolResult:
        return result

    def on_tool_call(self, call: ToolCall, transcript: Transcript) -> Decision:
        if call.name not in SINK_TOOLS:
            return Decision(Verdict.ALLOW, f"{self.name}: not a sink")
        leaking = any(contains_private(value, self.private_values) for value in call.args.values())
        if leaking:
            return Decision(Verdict.DENY, f"{self.name}: {call.name} carries private data")
        return Decision(Verdict.ALLOW, f"{self.name}: no private data in arguments")
