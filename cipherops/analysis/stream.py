"""Normalize ciphertext into analysis-friendly symbol streams."""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass

from cipherops.analysis.deck_parse import is_small_integer_alphabet, parse_integer_decks


@dataclass(frozen=True)
class AnalysisStream:
    raw: str
    text: str
    symbol_class: str
    alphabet_size: int
    preserves_spaces: bool
    preserves_punctuation: bool


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    printable = sum(1 for ch in text if ch.isprintable() and ch not in "\x00\x7f")
    return printable / len(text)


def _is_valid_hex_encoding(raw: str) -> bool:
    """True only when input plausibly encodes bytes as hex, not a small-integer deck."""
    stripped = re.sub(r"\s+", "", raw)
    if len(stripped) < 8:
        return False
    if not re.fullmatch(r"[0-9a-fA-F]+", stripped):
        return False
    # Digits-only strings without A-F are often integer decks (0-9, 0-4, etc.)
    if not re.search(r"[a-fA-F]", stripped):
        try:
            values = [int(ch) for ch in stripped]
        except ValueError:
            values = []
        if values and is_small_integer_alphabet(values, max_alphabet=16):
            return False
        # Space-separated single digits should never be hex
        if re.search(r"[\s,;]", raw):
            parts = re.split(r"[\s,;]+", raw.strip())
            if parts and all(len(p) == 1 and p.isdigit() for p in parts if p):
                return False
    if len(stripped) % 2 != 0:
        return False
    try:
        decoded = bytes.fromhex(stripped).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return False
    return _printable_ratio(decoded) >= 0.85


def _is_base64ish(text: str) -> bool:
    stripped = re.sub(r"\s+", "", text)
    if len(stripped) < 8:
        return False
    if not re.fullmatch(r"[A-Za-z0-9+/=]+", stripped):
        return False
    try:
        decoded = base64.b64decode(stripped, validate=True).decode("utf-8")
    except Exception:
        return False
    return _printable_ratio(decoded) >= 0.85


def normalize_stream(ciphertext: str | list[int], *, deck_size: int | None = None) -> AnalysisStream:
    if isinstance(ciphertext, list):
        values = [int(x) for x in ciphertext]
        text = " ".join(str(v) for v in values)
        size = deck_size or (max(values) + 1 if values else 0)
        return AnalysisStream(
            raw=text,
            text=text,
            symbol_class="integer",
            alphabet_size=size,
            preserves_spaces=True,
            preserves_punctuation=False,
        )

    raw = str(ciphertext)

    # Integer decks before alpha/hex — fixes 0-4 datasets misread as hex.
    parsed = parse_integer_decks(raw)
    if parsed is not None:
        decks, inferred_size = parsed
        flat = [v for row in decks for v in row]
        if flat and is_small_integer_alphabet(flat, max_alphabet=256):
            text = " ".join(str(v) for v in flat)
            size = deck_size or inferred_size
            return AnalysisStream(
                raw=raw,
                text=text,
                symbol_class="integer",
                alphabet_size=size,
                preserves_spaces=True,
                preserves_punctuation=False,
            )

    alpha = "".join(ch.upper() for ch in raw if ch.isalpha())
    if len(alpha) >= max(4, len(raw) // 3):
        return AnalysisStream(
            raw=raw,
            text=alpha,
            symbol_class="alpha",
            alphabet_size=26,
            preserves_spaces=" " in raw,
            preserves_punctuation=any(not ch.isalnum() and not ch.isspace() for ch in raw),
        )

    if _is_valid_hex_encoding(raw):
        hex_clean = re.sub(r"\s+", "", raw).upper()
        return AnalysisStream(
            raw=raw,
            text=hex_clean,
            symbol_class="hex",
            alphabet_size=16,
            preserves_spaces=False,
            preserves_punctuation=False,
        )

    if _is_base64ish(raw):
        b64_clean = re.sub(r"\s+", "", raw)
        return AnalysisStream(
            raw=raw,
            text=b64_clean,
            symbol_class="base64",
            alphabet_size=64,
            preserves_spaces=False,
            preserves_punctuation=False,
        )

    printable = "".join(ch for ch in raw if not ch.isspace())
    return AnalysisStream(
        raw=raw,
        text=printable or raw,
        symbol_class="printable",
        alphabet_size=len(set(printable)) if printable else 0,
        preserves_spaces=" " in raw,
        preserves_punctuation=any(not ch.isalnum() and not ch.isspace() for ch in raw),
    )
