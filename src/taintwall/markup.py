"""Detect directives hidden in markup rather than in codepoints.

This is the F3b half of Layer 1's detection: content that is fully legible to a
model but invisible to someone reading the rendered page, because it is buried in
off-screen CSS, a zero-size font, a comment, alt/aria text, a hidden input, a
noscript block, an SVG title, or a JSON-LD metadata block.

The detector runs on the raw markup a scraper would hand to the agent, using only
the standard-library HTML parser — no third-party dependency, and no attempt to
render CSS. It reports *that* content was concealed; deciding what to do about a
concealed instruction is the policy layer's job. Detection never rewrites: unlike
codepoint stripping, safely removing hidden markup would require rendering the
page, which a tool-boundary firewall cannot do.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser

# Style declarations that push content out of a sighted reader's view. Matched
# against the whitespace-stripped `style` attribute.
_HIDING_STYLE = re.compile(
    r"""
    display\s*:\s*none
    | visibility\s*:\s*hidden
    | font-size\s*:\s*0
    | opacity\s*:\s*0
    | clip-path\s*:\s*(?:inset|polygon|circle)
    | (?:left|top|right|bottom)\s*:\s*-\d{3,}         # off-screen absolute offset
    | text-indent\s*:\s*-\d{3,}
    """,
    re.IGNORECASE | re.VERBOSE,
)

# Foreground colour equal to background colour (white-on-white and friends). We
# only need to know they match, not what they are.
_COLOR = re.compile(r"(?<![-\w])color\s*:\s*(#[0-9a-f]{3,6}|\w+)", re.IGNORECASE)
_BG = re.compile(r"background(?:-color)?\s*:\s*(#[0-9a-f]{3,6}|\w+)", re.IGNORECASE)

# Attributes whose value reaches the model but not a sighted reader.
_CONCEALING_ATTRS = ("alt", "aria-label")

# Elements whose text content is not painted in the normal document flow.
_CONCEALING_TAGS = frozenset({"noscript", "template", "title"})


def _style_conceals(style: str) -> bool:
    if _HIDING_STYLE.search(style):
        return True
    colours = _COLOR.search(style)
    background = _BG.search(style)
    return bool(colours and background and colours.group(1).lower() == background.group(1).lower())


class _HiddenContentParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.hidden = False
        self._depth = 0  # nesting depth inside a concealing element

    def handle_comment(self, data: str) -> None:
        if data.strip():
            self.hidden = True

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        mapping = {name: (value or "") for name, value in attrs}

        if tag in _CONCEALING_TAGS:
            self._depth += 1

        if tag == "script" and "json" in mapping.get("type", "").lower():
            self._depth += 1

        if tag == "input" and mapping.get("type", "").lower() == "hidden":
            if mapping.get("value", "").strip():
                self.hidden = True

        for attr in _CONCEALING_ATTRS:
            if mapping.get(attr, "").strip():
                self.hidden = True

        style = mapping.get("style", "")
        if style and _style_conceals(style):
            self._depth += 1

    def handle_endtag(self, tag: str) -> None:
        if self._depth > 0:
            self._depth -= 1

    def handle_data(self, data: str) -> None:
        if self._depth > 0 and data.strip():
            self.hidden = True


def has_hidden_markup(text: str) -> bool:
    """True if the markup conceals text from a sighted reader.

    A heuristic over the standard-library HTML parser. It errs toward flagging
    concealment — that is the right bias for a signal that feeds a policy layer
    rather than a hard gate.
    """
    parser = _HiddenContentParser()
    parser.feed(text)
    parser.close()
    return parser.hidden
