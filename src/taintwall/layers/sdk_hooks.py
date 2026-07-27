"""Bridge the layer stack to the Claude Agent SDK's PreToolUse/PostToolUse hooks.

This is where taintwall stops being a harness and becomes a firewall: the same
layer stack the ablation measures runs against a real model, at the two enforcement
points the SDK exposes.

- **PreToolUse** returns a permission decision. A stack DENY (from the policy or
  provenance layers) becomes `permissionDecision: "deny"`, which the SDK honours
  even under `bypassPermissions` — the strongest enforcement primitive available.
- **PostToolUse** can replace a tool's output before the model ever sees it. Layer
  1's normalization runs here, so smuggled characters are stripped from retrieved
  content in flight.

The decision logic is pure and lives in `pre_tool_use_output` /
`post_tool_use_output`, so it is unit-tested in CI without the SDK installed. The
async hook factories and `build_hooks` are the thin SDK-facing wrappers, exercised
only on the live (real-model) path.
"""

from __future__ import annotations

from typing import Any

from taintwall.agent.fake_llm import Transcript
from taintwall.agent.tools import ToolCall, ToolResult
from taintwall.layers.base import LayerStack, Verdict

_VERDICT_TO_DECISION = {
    Verdict.DENY: "deny",
    Verdict.ASK: "ask",
    Verdict.SANITIZE: "allow",
    Verdict.ALLOW: "allow",
}


def bare_tool_name(name: str) -> str:
    """Strip an MCP tool prefix (`mcp__<server>__<action>`) down to the action."""
    return name.rsplit("__", 1)[-1]


def pre_tool_use_output(
    tool_name: str, tool_input: dict[str, Any], stack: LayerStack, *, intent: str
) -> dict[str, Any]:
    """The PreToolUse hook payload: a permission decision from the layer stack."""
    call = ToolCall(bare_tool_name(tool_name), {k: str(v) for k, v in tool_input.items()})
    decision = stack.decide(call, Transcript(intent))
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": _VERDICT_TO_DECISION[decision.verdict],
            "permissionDecisionReason": decision.reason,
        }
    }


def post_tool_use_output(tool_name: str, content: str, stack: LayerStack) -> dict[str, Any] | None:
    """The PostToolUse hook payload, or None when the stack leaves output unchanged.

    Returning None means "no rewrite" — the SDK keeps the original output. A payload
    with `updatedToolOutput` replaces the content the model will see.
    """
    cleaned = stack.apply_output(ToolResult(ToolCall(bare_tool_name(tool_name), {}), content))
    if cleaned.content == content:
        return None
    return {
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "updatedToolOutput": {"content": [{"type": "text", "text": cleaned.content}]},
        }
    }


def build_hooks(stack: LayerStack, *, intent: str) -> dict[str, Any]:
    """Build the `hooks` mapping for ClaudeAgentOptions from a layer stack.

    Imports the SDK lazily so this module is importable (and unit-testable) without
    claude-agent-sdk present.
    """
    from claude_agent_sdk import HookMatcher

    # The SDK requires async hook callables; ours delegate to pure sync logic.
    async def pre_hook(  # ruff: ignore[unused-async]
        input_data: dict[str, Any], tool_use_id: str | None, context: object
    ) -> dict[str, Any]:
        return pre_tool_use_output(
            str(input_data.get("tool_name", "")),
            dict(input_data.get("tool_input", {})),
            stack,
            intent=intent,
        )

    async def post_hook(  # ruff: ignore[unused-async]
        input_data: dict[str, Any], tool_use_id: str | None, context: object
    ) -> dict[str, Any]:
        content = _extract_text(input_data.get("tool_response"))
        payload = post_tool_use_output(str(input_data.get("tool_name", "")), content, stack)
        return payload or {}

    return {
        "PreToolUse": [HookMatcher(matcher="*", hooks=[pre_hook])],
        "PostToolUse": [HookMatcher(matcher="*", hooks=[post_hook])],
    }


def _extract_text(tool_response: object) -> str:
    """Pull the text out of an SDK tool-response payload, tolerant of shape."""
    if isinstance(tool_response, str):
        return tool_response
    if isinstance(tool_response, dict):
        blocks = tool_response.get("content")
        if isinstance(blocks, list):
            return "".join(str(b.get("text", "")) for b in blocks if isinstance(b, dict))
        return str(tool_response.get("text", ""))
    return ""
