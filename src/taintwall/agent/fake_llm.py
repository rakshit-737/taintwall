"""A scripted planner that follows a fixed plan and naively obeys retrieved text.

The single most important thing to understand about this module: the "attack
succeeded" signal it produces is *authored compliance*, not observed model
behaviour. :func:`interpret` is a hand-written rule for what a maximally-naive
agent would do, so it is never used to compute an attack-success rate. It exists
to make the deterministic track reproducible and to give the firewall stable
regression tests. Real attack-success numbers come from the Claude Agent SDK
runner instead.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, field

from taintwall.agent.tools import ToolCall, ToolResult

_EMAIL = r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+"
_URL = r"https?://[^\s\"'<>]+"
_PATH = r"[A-Za-z0-9._/-]+\.(?:txt|md|json|ya?ml|log|csv)"

DIRECTIVE_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(rf"\b(?:forward|send|cc|bcc|email)\b[^.]*?({_EMAIL})", re.I), "send_email"),
    (re.compile(rf"\b(?:post|upload|submit|fetch|call|report)\b[^.]*?({_URL})", re.I), "http_post"),
    (re.compile(rf"\bwrite\b[^.]*?\bto\s+({_PATH})", re.I), "write_file"),
)

_ARG_NAME = {"send_email": "to", "http_post": "url", "write_file": "path"}
_BODY_NAME = {"send_email": "body", "http_post": "data", "write_file": "content"}


def interpret(text: str) -> tuple[ToolCall, ...]:
    """Extract the tool calls a maximally-naive planner would make from text.

    Authored compliance, not observed behaviour — see the module docstring.
    """
    calls: list[ToolCall] = []
    for pattern, tool in DIRECTIVE_PATTERNS:
        match = pattern.search(text)
        if match is not None:
            calls.append(ToolCall(tool, {_ARG_NAME[tool]: match.group(1), _BODY_NAME[tool]: ""}))
    return tuple(calls)


@dataclass(slots=True)
class Transcript:
    intent: str
    results: list[ToolResult] = field(default_factory=list)
    texts: list[str] = field(default_factory=list)

    def latest_content(self) -> str:
        return self.results[-1].content if self.results else ""


@dataclass(frozen=True, slots=True)
class Plan:
    tool_calls: tuple[ToolCall, ...]
    text: str = ""


@dataclass(slots=True)
class FakeLLM:
    """Follows its script first, then naively obeys the last thing it read.

    When it obeys an exfiltration directive it copies the private data it has
    access to into the sink's body, exactly as a real "harvest now, decrypt
    later" attack does. This is what gives argument-level provenance something to
    catch on the deterministic track; script-driven (legitimate) calls are left
    alone and carry no private data.
    """

    script: Sequence[ToolCall]
    obey_injections: bool = True
    private_data: tuple[str, ...] = ()
    _step: int = 0
    _obeyed: set[str] = field(default_factory=set)

    def _fill_with_private_data(self, call: ToolCall) -> ToolCall:
        if not self.private_data:
            return call
        body_key = _BODY_NAME.get(call.name)
        if body_key is None:
            return call
        args = dict(call.args)
        args[body_key] = " ".join(self.private_data)
        return ToolCall(call.name, args)

    def next(self, transcript: Transcript) -> Plan:
        if self._step < len(self.script):
            call = self.script[self._step]
            self._step += 1
            return Plan((call,))

        if not self.obey_injections:
            return Plan(())

        content = transcript.latest_content()
        if content and content not in self._obeyed:
            self._obeyed.add(content)
            calls = interpret(content)
            if calls:
                return Plan(tuple(self._fill_with_private_data(c) for c in calls))
        return Plan((), text=f"Summary for: {transcript.intent}")
