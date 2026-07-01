"""Shared utilities for classical cipher implementations."""

from __future__ import annotations

import hashlib
import string

ALPHABET = string.ascii_uppercase


def clean_alpha(text: str, *, upper: bool = True) -> str:
    chars = [c.upper() if upper else c.lower() for c in text if c.isalpha()]
    return "".join(chars)


def char_index(char: str) -> int:
    return ord(char.upper()) - ord("A")


def index_char(index: int, *, upper: bool = True) -> str:
    base = ord("A") if upper else ord("a")
    return chr(index % 26 + base)


def preserve_case(original: str, transformed: str) -> str:
    """Apply transformed uppercase letters back onto original casing/punctuation."""
    result = []
    ti = 0
    for ch in original:
        if ch.isalpha():
            out = transformed[ti]
            result.append(out.upper() if ch.isupper() else out.lower())
            ti += 1
        else:
            result.append(ch)
    return "".join(result)


def mod_inverse(a: int, m: int = 26) -> int:
    a %= m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    raise ValueError(f"No modular inverse for a={a} mod {m}")


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def build_polybius_square(key: str = "", size: int = 5) -> list[list[str]]:
    """Build a Polybius square (5x5 or 6x6) from an optional keyword."""
    if size == 5:
        alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
        key = key.upper().replace("J", "I")
    else:
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        key = key.upper()

    seen = set()
    chars: list[str] = []
    for ch in key + alphabet:
        if ch in seen:
            continue
        seen.add(ch)
        chars.append(ch)

    return [chars[i * size : (i + 1) * size] for i in range(size)]


def polybius_coords(square: list[list[str]], char: str) -> tuple[int, int]:
    target = char.upper().replace("J", "I") if len(square) == 5 else char.upper()
    for r, row in enumerate(square):
        for c, cell in enumerate(row):
            if cell == target:
                return r, c
    raise ValueError(f"Character {char!r} not in Polybius square")


def _column_order(key: str) -> list[int]:
    key = clean_alpha(key)
    return sorted(range(len(key)), key=lambda i: (key[i], i))


def _column_heights(text_len: int, cols: int, rows: int) -> list[int]:
    rem = text_len % cols
    if rem == 0:
        return [rows] * cols
    return [rows if c < rem else rows - 1 for c in range(cols)]


def columnar_read(text: str, key: str) -> str:
    """Write text in rows, read columns sorted by key (encrypt)."""
    key = clean_alpha(key)
    if not key:
        raise ValueError("Columnar key must contain letters")

    cols = len(key)
    rows = (len(text) + cols - 1) // cols
    grid = [[""] * cols for _ in range(rows)]
    for idx, ch in enumerate(text):
        grid[idx // cols][idx % cols] = ch

    order = _column_order(key)
    return "".join(
        grid[r][c]
        for c in order
        for r in range(rows)
        if r * cols + c < len(text)
    )


def columnar_write(text: str, key: str) -> str:
    """Fill columns in key order, read rows left-to-right (decrypt)."""
    key = clean_alpha(key)
    cols = len(key)
    rows = (len(text) + cols - 1) // cols
    order = _column_order(key)
    heights = _column_heights(len(text), cols, rows)

    columns: dict[int, list[str]] = {}
    idx = 0
    for c in order:
        height = heights[c]
        columns[c] = list(text[idx : idx + height])
        idx += height

    return "".join(
        columns[c][r]
        for r in range(rows)
        for c in range(cols)
        if r < len(columns[c])
    )
