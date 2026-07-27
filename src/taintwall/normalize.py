"""Normalize and inspect untrusted text for codepoint-level smuggling.

This is Layer 1's core. Two operations that must stay separate: *neutralization*
removes the invisible carrier characters that let a directive hide from a human
while staying legible to a tokenizer, and *detection* reports what was found so a
later policy layer can act on "this content was carrying hidden instructions".

Homoglyph and mixed-script runs are detected but never rewritten — silently
"correcting" a Cyrillic character to its Latin lookalike would be a guess about
intent, and a guess is exactly what a security primitive must not make.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from enum import StrEnum

# Invisible carriers with no legitimate role in retrieved prose. Removed outright.
_ZERO_WIDTH = frozenset("​‌‍⁠⁢⁣⁤﻿­᠎")
_BIDI_CONTROLS = frozenset("‪‫‬‭‮⁦⁧⁨⁩")
_TAG_BLOCK = range(0xE0000, 0xE0080)
_VARIATION_SELECTORS = range(0xFE00, 0xFE10)

_LATIN_RANGE = ((0x41, 0x5A), (0x61, 0x7A))


class Finding(StrEnum):
    INVISIBLE_CODEPOINTS = "invisible_codepoints"
    BIDI_CONTROL = "bidi_control"
    MIXED_SCRIPT = "mixed_script"


@dataclass(frozen=True, slots=True)
class Normalization:
    text: str
    findings: frozenset[Finding]

    @property
    def is_clean(self) -> bool:
        return not self.findings


def _is_invisible_carrier(char: str) -> bool:
    if char in _ZERO_WIDTH or char in _BIDI_CONTROLS:
        return True
    code = ord(char)
    return code in _TAG_BLOCK or code in _VARIATION_SELECTORS


def strip_controls(text: str) -> str:
    """Remove invisible carrier characters, then apply NFKC.

    NFKC folds compatibility variants (fullwidth, ligatures) to their canonical
    form; it does not touch homoglyphs from a different script, which is why
    mixed-script is a detection concern rather than a normalization one.
    """
    without_carriers = "".join(c for c in text if not _is_invisible_carrier(c))
    return unicodedata.normalize("NFKC", without_carriers)


def _script_of(char: str) -> str | None:
    """A coarse script bucket for a cased letter: latin, cyrillic, greek, or None."""
    if not char.isalpha():
        return None
    code = ord(char)
    if any(low <= code <= high for low, high in _LATIN_RANGE):
        return "latin"
    try:
        name = unicodedata.name(char)
    except ValueError:
        return None
    if name.startswith("CYRILLIC"):
        return "cyrillic"
    if name.startswith("GREEK"):
        return "greek"
    return None


def _has_mixed_script_word(text: str) -> bool:
    """True if a single whitespace-delimited token mixes Latin with Cyrillic/Greek.

    Scoped to within a token so that ordinary multilingual text (an English
    sentence with a Greek word) does not trip the flag; only a *word* blending
    scripts — the homoglyph signature — does.
    """
    for token in text.split():
        scripts = {s for s in (_script_of(c) for c in token) if s is not None}
        if "latin" in scripts and ({"cyrillic", "greek"} & scripts):
            return True
    return False


def detect(text: str) -> frozenset[Finding]:
    findings: set[Finding] = set()
    if any(c in _BIDI_CONTROLS for c in text):
        findings.add(Finding.BIDI_CONTROL)
    if any(_is_invisible_carrier(c) for c in text):
        findings.add(Finding.INVISIBLE_CODEPOINTS)
    if _has_mixed_script_word(text):
        findings.add(Finding.MIXED_SCRIPT)
    return frozenset(findings)


def normalize(text: str) -> Normalization:
    return Normalization(text=strip_controls(text), findings=detect(text))
