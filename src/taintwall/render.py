"""Make invisible and direction-altering characters visible.

Writing a raw corpus payload to a terminal both corrupts the output and hides the
attack: the whole point of the tag block, zero-width characters, and bidirectional
overrides is that a human reviewer cannot see them. Every payload display in this
project goes through :func:`visualize`.
"""

from __future__ import annotations

INVISIBLE_MARKERS: dict[str, str] = {
    "​": "<ZWSP>",
    "‌": "<ZWNJ>",
    "‍": "<ZWJ>",
    "⁠": "<WJ>",
    "⁢": "<INVTIMES>",
    "⁣": "<INVSEP>",
    "⁤": "<INVPLUS>",
    "﻿": "<BOM>",
    "‪": "<LRE>",
    "‫": "<RLE>",
    "‬": "<PDF>",
    "‭": "<LRO>",
    "‮": "<RLO>",
    "⁦": "<LRI>",
    "⁧": "<RLI>",
    "⁨": "<FSI>",
    "⁩": "<PDI>",
    "­": "<SHY>",
    "᠎": "<MVS>",
}

_TAG_BLOCK_START = 0xE0000
_TAG_BLOCK_END = 0xE007F
_VARIATION_SELECTOR_START = 0xFE00
_VARIATION_SELECTOR_END = 0xFE0F


def visualize(text: str) -> str:
    """Replace invisible or direction-altering characters with visible markers.

    Tag-block characters (U+E0000-U+E007F) decode back to the ASCII letter they
    shadow, so ``<TAG:A>`` tells a reviewer that the payload carries a hidden "A".
    """
    out: list[str] = []
    for char in text:
        marker = INVISIBLE_MARKERS.get(char)
        if marker is not None:
            out.append(marker)
            continue
        code = ord(char)
        if _TAG_BLOCK_START <= code <= _TAG_BLOCK_END:
            out.append(f"<TAG:{chr(code - _TAG_BLOCK_START)}>")
            continue
        if _VARIATION_SELECTOR_START <= code <= _VARIATION_SELECTOR_END:
            out.append(f"<VS{code - _VARIATION_SELECTOR_START + 1}>")
            continue
        out.append(char)
    return "".join(out)


def has_invisibles(text: str) -> bool:
    """True when the text carries at least one character that renders as nothing."""
    return visualize(text) != text
