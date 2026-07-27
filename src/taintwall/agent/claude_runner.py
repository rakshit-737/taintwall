"""Drive the demo agent with a real model through the Claude Agent SDK.

This is the real-model track. It requires an interactive Claude Code login — the
SDK spawns the bundled `claude` CLI and honours the same credentials — so it
never runs in CI and incurs no marginal API cost against a metered key.

Phase 1 runs the agent undefended. Phase 2 attaches PreToolUse and PostToolUse
hooks at exactly this seam: a PreToolUse hook returning
``permissionDecision: "deny"`` is the Layer 3 enforcement point, and a
PostToolUse hook returning ``updatedToolOutput`` is the Layer 1 tagging point.
"""

from __future__ import annotations

import asyncio
import importlib.util
import os
from typing import Any

from taintwall.agent.fake_llm import Transcript
from taintwall.agent.loop import RunResult
from taintwall.agent.sinks import ExfilRecorder
from taintwall.agent.tools import ToolCall, ToolRegistry

_SERVER_NAME = "taintwall_demo"

# Input schema per demo tool, in the {arg_name: type} form the SDK's @tool
# decorator expects. Kept here rather than on the registry so the registry stays
# free of any SDK dependency.
_TOOL_SCHEMAS: dict[str, dict[str, type]] = {
    "read_email": {"id": str},
    "fetch_url": {"url": str},
    "read_file": {"path": str},
    "send_email": {"to": str, "subject": str, "body": str},
    "http_post": {"url": str, "data": str},
    "write_file": {"path": str, "content": str},
}


def sdk_available() -> bool:
    """True when claude-agent-sdk is importable. Never imports it or raises."""
    return importlib.util.find_spec("claude_agent_sdk") is not None


def build_sdk_tools(registry: ToolRegistry) -> list[Any]:
    """Expose every registry tool as an in-process SDK MCP tool."""
    from claude_agent_sdk import tool

    tools: list[Any] = []
    for name in registry.names():

        def make(tool_name: str, tool_schema: dict[str, type]) -> Any:
            # The SDK requires an async handler, and its @tool decorator is
            # untyped; neither is under our control.
            @tool(tool_name, f"taintwall demo tool: {tool_name}", tool_schema)  # type: ignore[untyped-decorator]
            async def _handler(args: dict[str, Any]) -> dict[str, Any]:  # ruff: ignore[unused-async]
                result = registry.call(ToolCall(tool_name, {k: str(v) for k, v in args.items()}))
                return {
                    "content": [{"type": "text", "text": result.content}],
                    "is_error": result.is_error,
                }

            return _handler

        tools.append(make(name, _TOOL_SCHEMAS.get(name, {})))
    return tools


def run_with_claude(
    *,
    intent: str,
    registry: ToolRegistry,
    recorder: ExfilRecorder,
    max_turns: int = 8,
) -> RunResult:
    """Run one real-model episode of the undefended demo agent."""
    if os.environ.get("TAINTWALL_DEMO_ACK") != "1":
        raise RuntimeError("set TAINTWALL_DEMO_ACK=1 to run the deliberately vulnerable agent")
    if not sdk_available():
        raise RuntimeError("install the demo extra: uv sync --extra demo")

    from claude_agent_sdk import (
        AssistantMessage,
        ClaudeAgentOptions,
        ClaudeSDKClient,
        TextBlock,
        ToolUseBlock,
        create_sdk_mcp_server,
    )

    server = create_sdk_mcp_server(
        name=_SERVER_NAME, version="0.1.0", tools=build_sdk_tools(registry)
    )
    options = ClaudeAgentOptions(
        mcp_servers={_SERVER_NAME: server},
        allowed_tools=[f"mcp__{_SERVER_NAME}__{name}" for name in registry.names()],
        max_turns=max_turns,
    )

    calls: list[ToolCall] = []
    texts: list[str] = []

    async def _drive() -> None:
        async with ClaudeSDKClient(options=options) as client:
            await client.query(intent)
            async for message in client.receive_response():
                if not isinstance(message, AssistantMessage):
                    continue
                for block in message.content:
                    if isinstance(block, ToolUseBlock):
                        bare = block.name.rsplit("__", 1)[-1]
                        calls.append(ToolCall(bare, dict(block.input)))
                    elif isinstance(block, TextBlock):
                        texts.append(block.text)

    asyncio.run(_drive())

    transcript = Transcript(intent=intent)
    transcript.texts.extend(texts)
    return RunResult(
        transcript=transcript,
        exfil=tuple(recorder.events),
        tool_calls=tuple(calls),
        blocked_calls=(),
        final_text=texts[-1] if texts else "",
    )
