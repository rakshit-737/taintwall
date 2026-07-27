"""The demo agent's tool registry and its six tools.

Three read tools are payload carriers; three sink tools are exfiltration
channels. The split matters for the policy layer later: a session declared
read-only has no business reaching a sink.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

from taintwall.agent.sinks import ExfilRecorder
from taintwall.agent.world import World

READ_TOOLS = frozenset({"read_email", "fetch_url", "read_file"})
SINK_TOOLS = frozenset({"send_email", "http_post", "write_file"})

ToolFn = Callable[[Mapping[str, str]], str]


@dataclass(frozen=True, slots=True)
class ToolCall:
    name: str
    args: Mapping[str, str]


@dataclass(frozen=True, slots=True)
class ToolResult:
    call: ToolCall
    content: str
    is_error: bool = False


@dataclass(slots=True)
class ToolRegistry:
    _fns: dict[str, ToolFn] = field(default_factory=dict)
    _capabilities: dict[str, str] = field(default_factory=dict)

    def register(self, name: str, fn: ToolFn, *, capability: str) -> None:
        self._fns[name] = fn
        self._capabilities[name] = capability

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._fns))

    def capability_of(self, name: str) -> str:
        return self._capabilities[name]

    def call(self, call: ToolCall) -> ToolResult:
        fn = self._fns.get(call.name)
        if fn is None:
            return ToolResult(call, f"error: no such tool {call.name!r}", is_error=True)
        try:
            return ToolResult(call, fn(call.args))
        except KeyError as exc:
            return ToolResult(call, f"error: not found {exc}", is_error=True)


def build_default_registry(world: World, recorder: ExfilRecorder) -> ToolRegistry:
    registry = ToolRegistry()

    registry.register("read_email", lambda a: world.emails[a["id"]], capability="read_email")
    registry.register("fetch_url", lambda a: world.pages[a["url"]], capability="fetch_url")
    registry.register("read_file", lambda a: world.files[a["path"]], capability="read_file")

    def send_email(args: Mapping[str, str]) -> str:
        recorder.record("send_email", args["to"], args.get("body", ""))
        return f"sent to {args['to']}"

    def http_post(args: Mapping[str, str]) -> str:
        recorder.record("http_post", args["url"], args.get("data", ""))
        return f"posted to {args['url']}"

    def write_file(args: Mapping[str, str]) -> str:
        recorder.record("write_file", args["path"], args.get("content", ""))
        world.files[args["path"]] = args.get("content", "")
        return f"wrote {args['path']}"

    registry.register("send_email", send_email, capability="send_email")
    registry.register("http_post", http_post, capability="http_post")
    registry.register("write_file", write_file, capability="write_file")
    return registry
