"""A small, transparent heuristic injection-likelihood score.

This is Layer 2's detector. It is deliberately simple and deliberately *not*
tuned to flatter the numbers — its mediocrity is the finding. The Phase 1 research
is unambiguous that content classifiers for prompt injection are evadable and
carry a real false-positive cost, and this scorer exists to show that on our own
corpus rather than assert it.

The score is a transparent weighted sum of three signals: authority spoofing,
imperative directives aimed at an action, and exfiltration/secrecy phrasing. It is
a *signal*, consumed by the policy layer as one input — it never gates a call on
its own. See docs/why-classifiers-fail.md.
"""

from __future__ import annotations

import re

_AUTHORITY = re.compile(
    r"""
    <\|im_start\|>
    | \bignore\s+(?:all\s+)?previous\b
    | \bdisregard\b
    | ^\s*system\s*:
    | \bpolicy\s+update\b
    | \badmin\s+note\b
    | \byou\s+are\s+(?:now|no\s+longer)\b
    | \bnew\s+directive\b
    | \bsupersedes\b
    | \boperator\s+instructions?\b
    """,
    re.IGNORECASE | re.VERBOSE,
)

_IMPERATIVE_TARGET = re.compile(
    r"""
    \b(?:forward|send|post|upload|submit|email|bcc|cc|exfiltrate|leak|write)\b
    [^.]*?
    (?:[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+ | https?://\S+ | [A-Za-z0-9._/-]+\.(?:txt|md|json|log|csv))
    """,
    re.IGNORECASE | re.VERBOSE,
)

_EXFIL_PHRASING = re.compile(
    r"""
    \bbase64\b
    | \bexfil\w*
    | \bcollector\b
    | \bdo\s+not\s+(?:mention|tell|reference|reveal)\b
    | \bbefore\s+(?:you\s+)?(?:reply|answer|respond|summari)
    | \bwithout\s+(?:the\s+user|telling)\b
    """,
    re.IGNORECASE | re.VERBOSE,
)

_WEIGHTS = ((_AUTHORITY, 0.5), (_IMPERATIVE_TARGET, 0.45), (_EXFIL_PHRASING, 0.35))


def heuristic_score(text: str) -> float:
    """An injection-likelihood score in [0, 1]. Transparent, weighted, untuned."""
    total = sum(weight for pattern, weight in _WEIGHTS if pattern.search(text))
    return min(1.0, total)


def flags(text: str, *, threshold: float) -> bool:
    return heuristic_score(text) >= threshold
