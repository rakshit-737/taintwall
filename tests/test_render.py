from __future__ import annotations

from taintwall.render import has_invisibles, visualize


def test_plain_text_is_unchanged() -> None:
    assert visualize("hello world") == "hello world"


def test_zero_width_space_becomes_visible() -> None:
    assert visualize("a​b") == "a<ZWSP>b"


def test_unicode_tag_characters_decode_to_their_ascii_letter() -> None:
    # U+E0041 is the tag form of "A".
    assert visualize("\U000e0041") == "<TAG:A>"


def test_a_full_tag_block_word_is_readable_again() -> None:
    hidden = "".join(chr(0xE0000 + ord(c)) for c in "hi")
    assert visualize(hidden) == "<TAG:h><TAG:i>"


def test_right_to_left_override_is_flagged() -> None:
    assert visualize("safe‮txt.exe") == "safe<RLO>txt.exe"


def test_variation_selector_is_flagged() -> None:
    assert visualize("x️") == "x<VS16>"


def test_has_invisibles_detects_hidden_characters() -> None:
    assert has_invisibles("clean text") is False
    assert has_invisibles("clean​text") is True
