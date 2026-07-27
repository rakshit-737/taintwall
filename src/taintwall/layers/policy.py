"""Layer 3: gate tool calls against the session's declared intent.

This is the action layer. It does not inspect content — it asks whether the
capability a call reaches is one the session was declared to need. A read-only
session that tries to send email is a violation no matter how the instruction
reached the agent, which is what makes this layer effective against injections
that defeat every content inspector.

Its blind spot is stated plainly in the design and in KNOWN_BYPASSES KB-005: an
attack that targets a capability the session *legitimately* holds is
indistinguishable from the legitimate use at this granularity. Closing that needs
argument-level provenance, the next increment.
"""

from __future__ import annotations

from dataclasses import dataclass

from taintwall.agent.fake_llm import Transcript
from taintwall.agent.tools import READ_TOOLS, ToolCall, ToolResult
from taintwall.layers.base import Decision, Verdict

# The capabilities a read-only session is permitted to reach. Read tools carry a
# capability equal to their own name in the default registry.
READ_ONLY_CAPABILITIES: frozenset[str] = READ_TOOLS


@dataclass(frozen=True, slots=True)
class SessionIntent:
    """What the session was declared to be allowed to do."""

    allowed_capabilities: frozenset[str]

    @classmethod
    def read_only(cls) -> SessionIntent:
        return cls(allowed_capabilities=READ_ONLY_CAPABILITIES)

    def allows(self, capability: str) -> bool:
        return capability in self.allowed_capabilities


# In the default registry a tool's capability equals its own name.
def _capability_of(call: ToolCall) -> str:
    return call.name


@dataclass(frozen=True, slots=True)
class PolicyLayer:
    intent: SessionIntent
    name: str = "L3-policy"

    def on_tool_output(self, result: ToolResult) -> ToolResult:
        return result

    def on_tool_call(self, call: ToolCall, transcript: Transcript) -> Decision:
        capability = _capability_of(call)
        if self.intent.allows(capability):
            return Decision(Verdict.ALLOW, f"{self.name}: {capability} within declared intent")
        return Decision(
            Verdict.DENY,
            f"{self.name}: {capability} not in declared intent "
            f"{sorted(self.intent.allowed_capabilities)}",
        )
