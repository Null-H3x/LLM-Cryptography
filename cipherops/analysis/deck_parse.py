"""Parse integer deck ciphertext from pasted text."""

from __future__ import annotations

import json
import re


def parse_integer_decks(raw: str | list | None) -> tuple[list[list[int]], int] | None:
    """
    Parse integer deck(s) from JSON, multi-line, or delimiter-separated text.

    Returns (messages, inferred_deck_size) or None if not a numeric deck.
    """
    if raw is None:
        return None
    if isinstance(raw, list):
        if raw and isinstance(raw[0], list):
            decks = [[int(x) for x in row] for row in raw]
        else:
            decks = [[int(x) for x in raw]]
        size = max(max(row) for row in decks if row) + 1 if decks else 0
        return decks, size

    text = str(raw).strip()
    if not text:
        return None

    if text.startswith("["):
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            return None
        if parsed and isinstance(parsed[0], list):
            decks = [[int(x) for x in row] for row in parsed]
        else:
            decks = [[int(x) for x in parsed]]
        size = max(max(row) for row in decks if row) + 1 if decks else 0
        return decks, size

    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if len(lines) > 1 and all(_is_numeric_line(ln) for ln in lines):
        decks = [_parse_int_line(ln) for ln in lines]
        size = max(max(row) for row in decks if row) + 1 if decks else 0
        return decks, size

    if _is_numeric_line(text):
        stripped = text.strip()
        if not re.search(r"[\s,;]", stripped) and stripped.isdigit():
            per_char = [int(c) for c in stripped]
            if per_char and is_small_integer_alphabet(per_char, max_alphabet=16):
                return [per_char], max(per_char) + 1
        values = _parse_int_line(text)
        return [values], max(values) + 1 if values else 0

    return None


def _is_numeric_line(text: str) -> bool:
    return bool(re.match(r"^[\d\s,;]+$", text.strip()))


def _parse_int_line(text: str) -> list[int]:
    text = text.strip()
    if text.startswith("["):
        return [int(x) for x in json.loads(text)]
    parts = re.split(r"[\s,;]+", text)
    return [int(p) for p in parts if p]


def is_small_integer_alphabet(values: list[int], *, max_alphabet: int = 256) -> bool:
    """True when values look like mod-N deck symbols, not hex nybbles."""
    if not values:
        return False
    hi = max(values)
    lo = min(values)
    if lo < 0:
        return False
    if hi >= 16 and any(v > 9 for v in values):
        return False
    # PAM-5 / 0-4 teaching alphabets, Noita mod 83, etc.
    return hi < max_alphabet
