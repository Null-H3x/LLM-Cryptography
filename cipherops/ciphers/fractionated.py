"""Fractionated and compound classical cipher implementations."""

from __future__ import annotations

from cipherops.ciphers.transposition import columnar_transposition, columnar_transposition_decrypt
from cipherops.ciphers.utils import build_polybius_square, clean_alpha, polybius_coords

ADFGX_ALPHABET = "ADFGX"
ADFGVX_ALPHABET = "ADFGVX"


def _coords_to_label(r: int, c: int, labels: str) -> str:
    return labels[r] + labels[c]


def _label_to_coords(label: str, labels: str) -> tuple[int, int]:
    return labels.index(label[0]), labels.index(label[1])


def adfgx(text: str, polybius_key: str, transposition_key: str) -> str:
    """ADFGX: 5x5 Polybius fractionation + columnar transposition."""
    square = build_polybius_square(polybius_key, size=5)
    fractionated = []
    for ch in clean_alpha(text):
        r, c = polybius_coords(square, ch)
        fractionated.append(_coords_to_label(r, c, ADFGX_ALPHABET))
    intermediate = "".join(fractionated)
    return columnar_transposition(intermediate, transposition_key)


def adfgx_decrypt(text: str, polybius_key: str, transposition_key: str) -> str:
    square = build_polybius_square(polybius_key, size=5)
    intermediate = columnar_transposition_decrypt(text, transposition_key)
    out = []
    for i in range(0, len(intermediate), 2):
        r, c = _label_to_coords(intermediate[i : i + 2], ADFGX_ALPHABET)
        out.append(square[r][c])
    return "".join(out)


def adfgvx(text: str, polybius_key: str, transposition_key: str) -> str:
    """ADFGVX: 6x6 Polybius fractionation + columnar transposition."""
    square = build_polybius_square(polybius_key, size=6)
    fractionated = []
    for ch in clean_alpha(text):
        ch = ch.upper()
        if ch == "J":
            ch = "I"
        r, c = polybius_coords(square, ch)
        fractionated.append(_coords_to_label(r, c, ADFGVX_ALPHABET))
    intermediate = "".join(fractionated)
    return columnar_transposition(intermediate, transposition_key)


def adfgvx_decrypt(text: str, polybius_key: str, transposition_key: str) -> str:
    square = build_polybius_square(polybius_key, size=6)
    intermediate = columnar_transposition_decrypt(text, transposition_key)
    out = []
    for i in range(0, len(intermediate), 2):
        r, c = _label_to_coords(intermediate[i : i + 2], ADFGVX_ALPHABET)
        out.append(square[r][c])
    return "".join(out)


def bifid(text: str, key: str = "", period: int = 0) -> str:
    """Bifid: Polybius row/col coordinates regrouped by period."""
    square = build_polybius_square(key, size=5)
    alpha = clean_alpha(text).replace("J", "I")
    if period <= 0:
        period = len(alpha)

    out = []
    for start in range(0, len(alpha), period):
        block = alpha[start : start + period]
        rows: list[str] = []
        cols: list[str] = []
        for ch in block:
            r, c = polybius_coords(square, ch)
            rows.append(str(r))
            cols.append(str(c))
        stream = "".join(rows + cols)
        for i in range(0, len(stream), 2):
            r = int(stream[i])
            c = int(stream[i + 1])
            out.append(square[r][c])
    return "".join(out)


def bifid_decrypt(text: str, key: str = "", period: int = 0) -> str:
    square = build_polybius_square(key, size=5)
    alpha = clean_alpha(text).replace("J", "I")
    if period <= 0:
        period = len(alpha)

    out = []
    for start in range(0, len(alpha), period):
        block = alpha[start : start + period]
        pairs = [polybius_coords(square, ch) for ch in block]
        stream: list[int] = []
        for row, col in pairs:
            stream.extend([row, col])
        half = len(block)
        rows = stream[:half]
        cols = stream[half:]
        for r, c in zip(rows, cols):
            out.append(square[r][c])
    return "".join(out)


def trifid(text: str, key: str = "", period: int = 0) -> str:
    """Trifid: 3x3x3 cube coordinates with trifid fractionation."""
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ0123456789"
    key = key.upper().replace("J", "I")
    seen = set()
    chars = ""
    for ch in key + alphabet:
        if ch not in seen:
            seen.add(ch)
            chars += ch
    cube = [[[None for _ in range(3)] for _ in range(3)] for _ in range(3)]
    idx = 0
    for layer in range(3):
        for r in range(3):
            for c in range(3):
                cube[layer][r][c] = chars[idx]
                idx += 1

    def locate(ch: str) -> tuple[int, int, int]:
        target = ch.upper().replace("J", "I")
        for layer in range(3):
            for r in range(3):
                for c in range(3):
                    if cube[layer][r][c] == target:
                        return layer, r, c
        raise ValueError(f"{ch!r} not in trifid cube")

    alpha = clean_alpha(text).replace("J", "I")
    if period <= 0:
        period = len(alpha)

    out = []
    for start in range(0, len(alpha), period):
        block = alpha[start : start + period]
        coords = []
        for ch in block:
            layer, r, c = locate(ch)
            coords.extend([str(layer), str(r), str(c)])
        for i in range(0, len(coords), 3):
            layer = int(coords[i])
            r = int(coords[i + 1])
            c = int(coords[i + 2])
            out.append(cube[layer][r][c])
    return "".join(out)


def trifid_decrypt(text: str, key: str = "", period: int = 0) -> str:
    # Encryption and decryption are symmetric for trifid fractionation
    return trifid(text, key=key, period=period)


def _default_straddle_layout() -> tuple[dict[str, str], dict[str, str]]:
    """Return fixed-width encode/decode maps for an unambiguous checkerboard."""
    rows = [
        "ETAOINSHRD",
        "LCFMPUGWYB",
        "VKJQZX",
    ]
    encode: dict[str, str] = {}
    decode: dict[str, str] = {}
    for row_idx, row in enumerate(rows):
        for col_idx, letter in enumerate(row):
            code = f"{row_idx}{col_idx}"
            encode[letter] = code
            decode[code] = letter
    return encode, decode


def straddle_checkerboard(text: str, layout: dict[str, str] | None = None) -> str:
    """Encode text with a straddle checkerboard (fixed-width numeric codes)."""
    encode, _ = _default_straddle_layout()
    if layout is not None:
        encode = layout
    return "".join(encode.get(ch, "99") for ch in clean_alpha(text))


def straddle_checkerboard_decrypt(text: str, layout: dict[str, str] | None = None) -> str:
    _, decode = _default_straddle_layout()
    if layout is not None:
        decode = {v: k for k, v in layout.items()}
    digits = "".join(ch for ch in text if ch.isdigit())
    return "".join(decode.get(digits[i : i + 2], "?") for i in range(0, len(digits), 2))


MORSE_CODE = {
    "A": ".-",
    "B": "-...",
    "C": "-.-.",
    "D": "-..",
    "E": ".",
    "F": "..-.",
    "G": "--.",
    "H": "....",
    "I": "..",
    "J": ".---",
    "K": "-.-",
    "L": ".-..",
    "M": "--",
    "N": "-.",
    "O": "---",
    "P": ".--.",
    "Q": "--.-",
    "R": ".-.",
    "S": "...",
    "T": "-",
    "U": "..-",
    "V": "...-",
    "W": ".--",
    "X": "-..-",
    "Y": "-.--",
    "Z": "--..",
}
MORSE_INVERSE = {v: k for k, v in MORSE_CODE.items()}


def fractionated_morse(text: str, substitution_key: str = "CIPHER") -> str:
    """Convert to Morse digits (1=dot, 2=dash), separate letters with 00, pair-map via Polybius."""
    segments = [
        MORSE_CODE[ch].replace(".", "1").replace("-", "2")
        for ch in clean_alpha(text)
    ]
    digit_stream = "33".join(segments)
    if len(digit_stream) % 2:
        digit_stream += "1"
    square = build_polybius_square(substitution_key, size=5)
    return "".join(
        square[int(digit_stream[i]) % 5][int(digit_stream[i + 1]) % 5]
        for i in range(0, len(digit_stream), 2)
    )


def fractionated_morse_decrypt(text: str, substitution_key: str = "CIPHER") -> str:
    square = build_polybius_square(substitution_key, size=5)
    digits = []
    for ch in clean_alpha(text):
        r, c = polybius_coords(square, ch)
        digits.append(str(r % 5))
        digits.append(str(c % 5))
    stream = "".join(digits)
    if len(stream) % 2:
        stream += "1"

    out = []
    for segment in stream.split("33"):
        if not segment:
            continue
        morse = segment.replace("1", ".").replace("2", "-")
        out.append(MORSE_INVERSE.get(morse, ""))
    return "".join(out)
