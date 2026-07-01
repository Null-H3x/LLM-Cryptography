"""Transposition cipher implementations."""

from __future__ import annotations

from cipherops.ciphers.utils import clean_alpha, columnar_read, columnar_write


def rail_fence(text: str, rails: int) -> str:
    """Write text in a zigzag across `rails` rows, read row by row."""
    if rails < 2:
        raise ValueError("Rail count must be >= 2")
    if rails == 1:
        return text

    fence: list[list[str]] = [[] for _ in range(rails)]
    rail = 0
    direction = 1
    for ch in text:
        fence[rail].append(ch)
        if rail == 0:
            direction = 1
        elif rail == rails - 1:
            direction = -1
        rail += direction

    return "".join("".join(row) for row in fence)


def rail_fence_decrypt(text: str, rails: int) -> str:
    if rails < 2:
        return text

    n = len(text)
    pattern = list(range(rails)) + list(range(rails - 2, 0, -1))
    counts = [0] * rails
    for i in range(n):
        counts[pattern[i % len(pattern)]] += 1

    rows: list[list[str]] = []
    idx = 0
    for count in counts:
        rows.append(list(text[idx : idx + count]))
        idx += count

    result = []
    row_idx = [0] * rails
    for i in range(n):
        r = pattern[i % len(pattern)]
        result.append(rows[r][row_idx[r]])
        row_idx[r] += 1
    return "".join(result)


def columnar_transposition(text: str, key: str) -> str:
    """Columnar transposition: write rows, read columns sorted by key."""
    return columnar_read(text, key)


def columnar_transposition_decrypt(text: str, key: str) -> str:
    return columnar_write(text, key)
