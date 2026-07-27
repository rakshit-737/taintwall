"""Trust labels and the argument-level provenance check.

A `Tainted[T]` carries a value together with a trust label and its source. The
provenance layer uses it in its simplest honest form: the session's secrets are
PRIVATE, and a sink call whose arguments carry a private value is a leak, even
when the session legitimately holds the sink capability.

The limit is stated in KNOWN_BYPASSES KB-001 and KB-005: this is a *verbatim*
check. Private data that has been transformed — paraphrased, or re-encoded so the
bytes differ — is not caught, because string-level provenance cannot follow a
value through a semantic transformation. Simple, reversible encodings (base64,
hex) are covered by decoding before the check; a genuine paraphrase is not.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from enum import StrEnum
from typing import Generic, TypeVar

T = TypeVar("T")


class TrustLabel(StrEnum):
    PRIVATE = "private"
    UNTRUSTED = "untrusted"
    PUBLIC = "public"


@dataclass(frozen=True, slots=True)
class Tainted(Generic[T]):
    value: T
    label: TrustLabel
    source: str

    @property
    def is_private(self) -> bool:
        return self.label is TrustLabel.PRIVATE


def _candidate_decodings(text: str) -> tuple[str, ...]:
    """The text itself plus simple reversible decodings a leak might hide behind.

    Covers verbatim, base64, and hex. Deliberately does NOT attempt to reverse a
    semantic transformation (a paraphrase) - that is the documented KB-001 limit.
    """
    candidates = [text]
    stripped = text.strip()
    for decoder in (_try_base64, _try_hex):
        decoded = decoder(stripped)
        if decoded is not None:
            candidates.append(decoded)
    return tuple(candidates)


def _try_base64(text: str) -> str | None:
    if len(text) < 8 or len(text) % 4 != 0:
        return None
    try:
        return base64.b64decode(text, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None


def _try_hex(text: str) -> str | None:
    if len(text) < 8 or len(text) % 2 != 0:
        return None
    try:
        return bytes.fromhex(text).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None


def contains_private(text: str, private_values: frozenset[str]) -> bool:
    """True if any private value appears in the text, verbatim or simply encoded."""
    if not private_values:
        return False
    haystacks = _candidate_decodings(text)
    return any(secret in hay for secret in private_values for hay in haystacks)
