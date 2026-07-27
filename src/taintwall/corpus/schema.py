"""Frozen record types for the attack and benign corpora.

Two schema decisions carry most of the weight:

``payload_sha256`` is computed over the *decoded* UTF-8 bytes and verified on every
load, so a CRLF translation, a stray BOM, or an editor auto-trim fails loudly rather
than silently changing what an attack says.

``source`` is required on every record. It is the field almost nobody ships, and it
is what lets the published artifact be filtered down to redistributable records when
a downstream consumer has a licence constraint we do not.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Family(StrEnum):
    """Attack families. F3 is split because its two halves need different detectors."""

    F1 = "F1"  # instruction override / authority spoof
    F2 = "F2"  # benign business-language override
    F3A = "F3a"  # invisible codepoints
    F3B = "F3b"  # hidden markup
    F4 = "F4"  # client-render exfiltration
    F5 = "F5"  # agent-action exfiltration
    F6 = "F6"  # MCP tool-metadata poisoning
    F7 = "F7"  # persistence / delayed trigger
    F8 = "F8"  # confused deputy across trust tiers
    F9 = "F9"  # tool-response / error poisoning


class Channel(StrEnum):
    WEB = "web"
    EMAIL = "email"
    FILE = "file"
    TOOL_OUTPUT = "tool_output"
    RAG = "rag"
    MCP = "mcp"


class Vector(StrEnum):
    DIRECT = "direct"
    INDIRECT = "indirect"
    TRIGGERED = "triggered"


class PayloadEncoding(StrEnum):
    RAW = "raw"
    BASE64 = "base64"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class BaselineOutcome(StrEnum):
    SUCCEEDS = "succeeds"
    BLOCKED = "blocked"
    FAILS = "fails"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class Source:
    name: str
    url: str
    license: str


@dataclass(frozen=True, slots=True)
class References:
    owasp_llm: str | None = None
    owasp_asi: str | None = None
    owasp_mcp: str | None = None
    mitre_atlas: str | None = None
    cwe: str | None = None


@dataclass(frozen=True, slots=True)
class ExpectedBehavior:
    should_be_flagged: bool
    expected_detectors: tuple[str, ...]
    policy_violation: str | None
    baseline_outcome: BaselineOutcome


@dataclass(frozen=True, slots=True)
class AttackRecord:
    id: str
    family: Family
    technique: str
    channel: Channel
    vector: Vector
    payload: str
    payload_encoding: PayloadEncoding
    payload_sha256: str
    target_capability: str
    expected_behavior: ExpectedBehavior
    severity: Severity
    references: References
    source: Source
    adaptive: bool = False
    notes: str | None = None


@dataclass(frozen=True, slots=True)
class BenignRecord:
    id: str
    text: str
    stratum: str
    source: Source
    difficulty: str | None = None
