from __future__ import annotations

import base64

from taintwall.provenance import Tainted, TrustLabel, contains_private

SECRETS = frozenset({"sk-SECRET-042"})


def test_verbatim_private_value_is_found() -> None:
    assert contains_private("here is the key sk-SECRET-042 for you", SECRETS) is True


def test_base64_encoded_private_value_is_found() -> None:
    encoded = base64.b64encode(b"sk-SECRET-042").decode("ascii")
    assert contains_private(encoded, SECRETS) is True


def test_hex_encoded_private_value_is_found() -> None:
    encoded = b"sk-SECRET-042".hex()
    assert contains_private(encoded, SECRETS) is True


def test_unrelated_text_is_clean() -> None:
    assert contains_private("the quarterly numbers look stable", SECRETS) is False


def test_no_private_values_means_nothing_matches() -> None:
    assert contains_private("sk-SECRET-042", frozenset()) is False


def test_a_paraphrase_is_not_caught_which_is_the_documented_limit() -> None:
    # KB-001 / KB-005: string-level provenance cannot follow a value through a
    # semantic transformation. "the key that starts with sk" does not contain the
    # secret's bytes, so it is not caught. This test pins that known gap.
    assert contains_private("the key that starts with sk and ends in 042", SECRETS) is False


def test_tainted_carries_a_label_and_source() -> None:
    t: Tainted[str] = Tainted("sk-SECRET-042", TrustLabel.PRIVATE, source="world.secrets")
    assert t.is_private is True
    assert t.value == "sk-SECRET-042"
    assert Tainted("hello", TrustLabel.PUBLIC, source="x").is_private is False
