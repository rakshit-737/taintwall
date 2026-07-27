"""Strict YAML loader for the labelled corpora.

Unknown fields are rejected rather than ignored. A typo in a corpus record is a
data-quality bug that would otherwise silently disable a label, and labels are the
whole contribution here.
"""

from __future__ import annotations

import base64
import hashlib
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml

from taintwall.corpus.schema import (
    AttackRecord,
    BaselineOutcome,
    BenignRecord,
    Channel,
    ExpectedBehavior,
    Family,
    PayloadEncoding,
    References,
    Severity,
    Source,
    Vector,
)


def _corpus_root() -> Path:
    override = os.environ.get("TAINTWALL_CORPUS_ROOT")
    if override:
        return Path(override)
    return Path(__file__).resolve().parents[3] / "corpus"


CORPUS_ROOT = _corpus_root()
ATTACKS_DIR = CORPUS_ROOT / "attacks"
BENIGN_DIR = CORPUS_ROOT / "benign"

_RECORD_FIELDS = frozenset(
    {
        "id",
        "family",
        "technique",
        "channel",
        "vector",
        "payload",
        "payload_encoding",
        "payload_sha256",
        "target_capability",
        "expected_behavior",
        "severity",
        "references",
        "source",
        "adaptive",
        "notes",
    }
)
_BEHAVIOR_FIELDS = frozenset(
    {"should_be_flagged", "expected_detectors", "policy_violation", "baseline_outcome"}
)
_REFERENCE_FIELDS = frozenset({"owasp_llm", "owasp_asi", "owasp_mcp", "mitre_atlas", "cwe"})
_SOURCE_FIELDS = frozenset({"name", "url", "license"})
_BENIGN_FIELDS = frozenset({"id", "text", "stratum", "difficulty", "source"})


class CorpusError(Exception):
    """A corpus file is malformed, or a payload does not match its recorded hash."""


def compute_sha256(payload: str) -> str:
    """Hash the decoded payload text, so the digest is encoding-independent."""
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _reject_unknown(raw: Mapping[str, Any], allowed: frozenset[str], where: str) -> None:
    extra = set(raw) - allowed
    if extra:
        raise CorpusError(f"{where}: unknown field(s) {sorted(extra)}")


def _load_yaml(path: Path) -> list[dict[str, Any]]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "records" not in data:
        raise CorpusError(f"{path}: expected a top-level 'records' list")
    records = data["records"]
    if not isinstance(records, list):
        raise CorpusError(f"{path}: 'records' must be a list")
    return records


def _parse_record(raw: Mapping[str, Any], path: Path) -> AttackRecord:
    where = f"{path.name}:{raw.get('id', '<no id>')}"
    _reject_unknown(raw, _RECORD_FIELDS, where)

    encoding = PayloadEncoding(raw["payload_encoding"])
    stored = str(raw["payload"])
    if encoding is PayloadEncoding.BASE64:
        try:
            payload = base64.b64decode(stored, validate=True).decode("utf-8")
        except Exception as exc:
            raise CorpusError(f"{where}: payload is not valid base64 UTF-8 ({exc})") from exc
    else:
        payload = stored

    actual = compute_sha256(payload)
    if actual != raw["payload_sha256"]:
        raise CorpusError(
            f"{where}: payload_sha256 mismatch (recorded {raw['payload_sha256']}, actual {actual})"
        )

    behavior_raw = raw["expected_behavior"]
    _reject_unknown(behavior_raw, _BEHAVIOR_FIELDS, f"{where}.expected_behavior")
    behavior = ExpectedBehavior(
        should_be_flagged=bool(behavior_raw["should_be_flagged"]),
        expected_detectors=tuple(behavior_raw.get("expected_detectors") or ()),
        policy_violation=behavior_raw.get("policy_violation"),
        baseline_outcome=BaselineOutcome(behavior_raw["baseline_outcome"]),
    )

    references_raw = raw.get("references") or {}
    _reject_unknown(references_raw, _REFERENCE_FIELDS, f"{where}.references")
    source_raw = raw["source"]
    _reject_unknown(source_raw, _SOURCE_FIELDS, f"{where}.source")

    return AttackRecord(
        id=str(raw["id"]),
        family=Family(raw["family"]),
        technique=str(raw["technique"]),
        channel=Channel(raw["channel"]),
        vector=Vector(raw["vector"]),
        payload=payload,
        payload_encoding=encoding,
        payload_sha256=str(raw["payload_sha256"]),
        target_capability=str(raw["target_capability"]),
        expected_behavior=behavior,
        severity=Severity(raw["severity"]),
        references=References(**references_raw),
        source=Source(**source_raw),
        adaptive=bool(raw.get("adaptive", False)),
        notes=raw.get("notes"),
    )


def load_attack_file(path: Path) -> tuple[AttackRecord, ...]:
    return tuple(_parse_record(raw, path) for raw in _load_yaml(path))


def load_attacks(root: Path | None = None) -> tuple[AttackRecord, ...]:
    directory = ATTACKS_DIR if root is None else root
    if not directory.is_dir():
        return ()
    records: list[AttackRecord] = []
    for path in sorted(directory.glob("*.yaml")):
        records.extend(load_attack_file(path))
    return tuple(records)


def load_benign(root: Path | None = None) -> tuple[BenignRecord, ...]:
    directory = BENIGN_DIR if root is None else root
    if not directory.is_dir():
        return ()
    records: list[BenignRecord] = []
    for path in sorted(directory.glob("*.yaml")):
        for raw in _load_yaml(path):
            where = f"{path.name}:{raw.get('id', '<no id>')}"
            _reject_unknown(raw, _BENIGN_FIELDS, where)
            source_raw = raw["source"]
            _reject_unknown(source_raw, _SOURCE_FIELDS, f"{where}.source")
            records.append(
                BenignRecord(
                    id=str(raw["id"]),
                    text=str(raw["text"]),
                    stratum=str(raw["stratum"]),
                    difficulty=raw.get("difficulty"),
                    source=Source(**source_raw),
                )
            )
    return tuple(records)
