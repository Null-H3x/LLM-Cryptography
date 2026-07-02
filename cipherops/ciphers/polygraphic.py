"""Polygraphic and matrix-based cipher implementations."""

from __future__ import annotations

import numpy as np

from cipherops.ciphers.utils import ALPHABET, char_index, clean_alpha, mod_inverse


def _playfair_matrix(key: str) -> list[list[str]]:
    key = key.upper().replace("J", "I")
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    seen = set()
    chars = ""
    for ch in key + alphabet:
        if ch not in seen:
            seen.add(ch)
            chars += ch
    return [list(chars[i * 5 : (i + 1) * 5]) for i in range(5)]


def _find_position(matrix: list[list[str]], char: str, *, merge_j: bool = True) -> tuple[int, int]:
    target = char.upper().replace("J", "I") if merge_j else char.upper()
    for r, row in enumerate(matrix):
        for c, cell in enumerate(row):
            if cell == target:
                return r, c
    raise ValueError(f"{char!r} not in matrix")


def _prepare_digraphs(text: str, *, merge_j: bool = True) -> list[tuple[str, str]]:
    text = clean_alpha(text)
    if merge_j:
        text = text.replace("J", "I")
    pairs: list[tuple[str, str]] = []
    i = 0
    while i < len(text):
        if i + 1 >= len(text):
            pairs.append((text[i], "X"))
            break
        if text[i] == text[i + 1]:
            pairs.append((text[i], "X"))
            i += 1
        else:
            pairs.append((text[i], text[i + 1]))
            i += 2
    return pairs


def playfair(text: str, key: str, *, decrypt: bool = False) -> str:
    matrix = _playfair_matrix(key)
    pairs = _prepare_digraphs(text, merge_j=not decrypt)
    out = []
    for p1, p2 in pairs:
        r1, c1 = _find_position(matrix, p1)
        r2, c2 = _find_position(matrix, p2)
        if r1 == r2:
            dc = -1 if decrypt else 1
            out.append(matrix[r1][(c1 + dc) % 5] + matrix[r2][(c2 + dc) % 5])
        elif c1 == c2:
            dr = -1 if decrypt else 1
            out.append(matrix[(r1 + dr) % 5][c1] + matrix[(r2 + dr) % 5][c2])
        else:
            if decrypt:
                out.append(matrix[r1][c2] + matrix[r2][c1])
            else:
                out.append(matrix[r1][c2] + matrix[r2][c1])
    return "".join(out)


def _four_square_matrices(key1: str, key2: str) -> tuple[list[list[str]], list[list[str]], list[list[str]], list[list[str]]]:
    def build(key: str) -> list[list[str]]:
        key = key.upper().replace("J", "I")
        alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
        seen = set()
        chars = ""
        for ch in key + alphabet:
            if ch not in seen:
                seen.add(ch)
                chars += ch
        return [list(chars[i * 5 : (i + 1) * 5]) for i in range(5)]

    tl = build(key1)
    tr = [list(ALPHABET[i * 5 : (i + 1) * 5]) for i in range(5)]
    bl = [list(ALPHABET[i * 5 : (i + 1) * 5]) for i in range(5)]
    br = build(key2)
    return tl, tr, bl, br


def _ciphertext_pairs(text: str) -> list[tuple[str, str]]:
    """Split even-length ciphertext into consecutive digraphs (no plaintext padding rules)."""
    text = clean_alpha(text)
    if len(text) % 2:
        text += "X"
    return [(text[i], text[i + 1]) for i in range(0, len(text), 2)]


def four_square(text: str, key1: str, key2: str, *, decrypt: bool = False) -> str:
    tl, tr, bl, br = _four_square_matrices(key1, key2)
    pairs = _ciphertext_pairs(text) if decrypt else _prepare_digraphs(text, merge_j=True)
    out = []
    for left, right in pairs:
        if decrypt:
            r1, c1 = _find_position(tr, left, merge_j=False)
            r2, c2 = _find_position(bl, right, merge_j=False)
            out.append(tl[r1][c2] + br[r2][c1])
        else:
            r1, c1 = _find_position(tl, left, merge_j=True)
            r2, c2 = _find_position(br, right, merge_j=True)
            out.append(tr[r1][c2] + bl[r2][c1])
    return "".join(out)


def _mod_matrix_inverse(matrix: np.ndarray, mod: int = 26) -> np.ndarray:
    det = int(round(np.linalg.det(matrix))) % mod
    det_inv = mod_inverse(det, mod)
    adj = np.round(np.linalg.inv(matrix) * np.linalg.det(matrix)).astype(int) % mod
    return (det_inv * adj) % mod


def hill(text: str, key_matrix: list[list[int]], *, decrypt: bool = False) -> str:
    h = np.array(key_matrix, dtype=int)
    n = h.shape[0]
    alpha = clean_alpha(text)
    values = [char_index(c) for c in alpha]
    while len(values) % n:
        values.append(char_index("X"))

    mat = _mod_matrix_inverse(h) if decrypt else h
    out = []
    for i in range(0, len(values), n):
        block = np.array(values[i : i + n])
        result = (mat @ block) % 26
        out.extend(int(x) for x in result.tolist())
    return "".join(ALPHABET[v] for v in out)
