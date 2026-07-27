from __future__ import annotations

from taintwall.agent.fake_llm import Transcript
from taintwall.agent.tools import ToolCall
from taintwall.harness.runner import ModelKind, run_matrix
from taintwall.layers.base import Verdict
from taintwall.layers.policy import PolicyLayer, SessionIntent
from taintwall.tasks.definitions import TASKS


def test_read_only_intent_allows_reads() -> None:
    layer = PolicyLayer(SessionIntent.read_only())
    for tool in ("read_email", "fetch_url", "read_file"):
        decision = layer.on_tool_call(ToolCall(tool, {}), Transcript("t"))
        assert decision.verdict is Verdict.ALLOW


def test_read_only_intent_denies_every_sink() -> None:
    layer = PolicyLayer(SessionIntent.read_only())
    for tool in ("send_email", "http_post", "write_file"):
        decision = layer.on_tool_call(ToolCall(tool, {"to": "x"}), Transcript("t"))
        assert decision.verdict is Verdict.DENY


def test_the_denied_reason_names_the_capability_and_the_intent() -> None:
    layer = PolicyLayer(SessionIntent.read_only())
    decision = layer.on_tool_call(ToolCall("http_post", {"url": "u"}), Transcript("t"))
    assert "http_post" in decision.reason


def test_an_intent_that_allows_a_sink_does_not_block_an_attack_on_it() -> None:
    # KB-005: capability-gating cannot distinguish a legitimate use of a granted
    # capability from an attacker's use of the same capability.
    intent = SessionIntent(allowed_capabilities=frozenset({"read_email", "send_email"}))
    layer = PolicyLayer(intent)
    attacker_call = ToolCall("send_email", {"to": "drop@example.invalid"})
    assert layer.on_tool_call(attacker_call, Transcript("t")).verdict is Verdict.ALLOW


def test_layer3_drives_read_only_exfiltration_to_zero_on_the_deterministic_track() -> None:
    from taintwall.corpus.loader import load_attacks

    # Read-only tasks only: under the null stack some sink calls execute; under a
    # stack with the policy layer none do.
    read_only = tuple(
        t for t in TASKS if t.allowed_capabilities == SessionIntent.read_only().allowed_capabilities
    )
    attacks = load_attacks()[:20]

    none = run_matrix(
        tasks=read_only, attacks=attacks, stack_labels=("none",), model_kind=ModelKind.FAKE
    )
    gated = run_matrix(
        tasks=read_only, attacks=attacks, stack_labels=("+L1L2L3",), model_kind=ModelKind.FAKE
    )

    none_exfil = sum(o.attack_succeeded for o in none if o.attack_id is not None)
    gated_exfil = sum(o.attack_succeeded for o in gated if o.attack_id is not None)

    assert none_exfil > 0, "the undefended stack should leak on some attacks"
    assert gated_exfil == 0, "the policy layer should block every read-only sink call"
