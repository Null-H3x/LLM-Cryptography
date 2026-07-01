"""Classical monoalphabetic and polyalphabetic cipher implementations."""

from __future__ import annotations

from cipherops.ciphers.utils import (
    ALPHABET,
    char_index,
    clean_alpha,
    index_char,
    mod_inverse,
    preserve_case,
)


def atbash(text: str) -> str:
    """E(x) = (25 - x) mod 26. Self-reciprocal."""
    transformed = "".join(index_char(25 - char_index(c)) for c in clean_alpha(text))
    return preserve_case(text, transformed)


def caesar(text: str, shift: int) -> str:
    """E_k(x) = (x + k) mod 26."""
    transformed = "".join(index_char(char_index(c) + shift) for c in clean_alpha(text))
    return preserve_case(text, transformed)


def rot13(text: str) -> str:
    return caesar(text, 13)


def affine(text: str, a: int, b: int) -> str:
    """E_{a,b}(x) = (a*x + b) mod 26."""
    if __import__("math").gcd(a, 26) != 1:
        raise ValueError(f"Invalid affine key a={a}; gcd(a,26) must be 1")
    transformed = "".join(index_char(a * char_index(c) + b) for c in clean_alpha(text))
    return preserve_case(text, transformed)


def affine_decrypt(text: str, a: int, b: int) -> str:
    a_inv = mod_inverse(a)
    transformed = "".join(index_char(a_inv * (char_index(c) - b)) for c in clean_alpha(text))
    return preserve_case(text, transformed)


def beaufort(text: str, key: str) -> str:
    """E(x) = (k - x) mod 26. Self-reciprocal."""
    key = clean_alpha(key)
    if not key:
        raise ValueError("Beaufort key required")
    out = []
    ki = 0
    for ch in text:
        if ch.isalpha():
            k = char_index(key[ki % len(key)])
            out.append(index_char(k - char_index(ch), upper=ch.isupper()))
            ki += 1
        else:
            out.append(ch)
    return "".join(out)


def vigenere(text: str, key: str) -> str:
    """E_K(x_i) = (x_i + k_{i mod m}) mod 26."""
    key = clean_alpha(key)
    if not key:
        raise ValueError("Vigenere key required")
    out = []
    ki = 0
    for ch in text:
        if ch.isalpha():
            k = char_index(key[ki % len(key)])
            out.append(index_char(char_index(ch) + k, upper=ch.isupper()))
            ki += 1
        else:
            out.append(ch)
    return "".join(out)


def vigenere_decrypt(text: str, key: str) -> str:
    key = clean_alpha(key)
    out = []
    ki = 0
    for ch in text:
        if ch.isalpha():
            k = char_index(key[ki % len(key)])
            out.append(index_char(char_index(ch) - k, upper=ch.isupper()))
            ki += 1
        else:
            out.append(ch)
    return "".join(out)


def gronsfeld(text: str, numeric_key: str) -> str:
    """Vigenere variant with decimal digit shifts."""
    if not numeric_key or not numeric_key.isdigit():
        raise ValueError("Gronsfeld key must be numeric")
    out = []
    ki = 0
    for ch in text:
        if ch.isalpha():
            k = int(numeric_key[ki % len(numeric_key)])
            out.append(index_char(char_index(ch) + k, upper=ch.isupper()))
            ki += 1
        else:
            out.append(ch)
    return "".join(out)


def gronsfeld_decrypt(text: str, numeric_key: str) -> str:
    if not numeric_key or not numeric_key.isdigit():
        raise ValueError("Gronsfeld key must be numeric")
    out = []
    ki = 0
    for ch in text:
        if ch.isalpha():
            k = int(numeric_key[ki % len(numeric_key)])
            out.append(index_char(char_index(ch) - k, upper=ch.isupper()))
            ki += 1
        else:
            out.append(ch)
    return "".join(out)


def nihilist(text: str, numeric_key: str, *, polybius_key: str = "NIHILIST") -> str:
    """
    Nihilist cipher: Polybius coordinates + numeric key addition mod 10 per digit.
    """
    if not numeric_key or not numeric_key.isdigit():
        raise ValueError("Nihilist key must be numeric")
    from cipherops.ciphers.utils import build_polybius_square, polybius_coords

    square = build_polybius_square(polybius_key, size=5)
    digits: list[str] = []
    ki = 0
    for ch in text:
        if ch.isalpha():
            r, c = polybius_coords(square, ch)
            d1, d2 = r + 1, c + 1
            k1 = int(numeric_key[ki % len(numeric_key)])
            k2 = int(numeric_key[(ki + 1) % len(numeric_key)])
            digits.append(str((d1 + k1) % 10))
            digits.append(str((d2 + k2) % 10))
            ki += 2
        else:
            digits.append(ch)
    return "".join(digits)


def nihilist_decrypt(text: str, numeric_key: str, *, polybius_key: str = "NIHILIST") -> str:
    if not numeric_key or not numeric_key.isdigit():
        raise ValueError("Nihilist key must be numeric")
    from cipherops.ciphers.utils import build_polybius_square

    square = build_polybius_square(polybius_key, size=5)
    digits = "".join(ch for ch in text if ch.isdigit())
    ki = 0
    letters: list[str] = []
    for i in range(0, len(digits), 2):
        d1 = int(digits[i])
        d2 = int(digits[i + 1])
        k1 = int(numeric_key[ki % len(numeric_key)])
        k2 = int(numeric_key[(ki + 1) % len(numeric_key)])
        r = (d1 - k1) % 10
        c = (d2 - k2) % 10
        if not 1 <= r <= 5 or not 1 <= c <= 5:
            raise ValueError(f"Invalid Polybius coordinates after decrypt: {r},{c}")
        letters.append(square[r - 1][c - 1])
        ki += 2
    out: list[str] = []
    li = 0
    di = 0
    for ch in text:
        if ch.isdigit():
            if di % 2 == 0:
                out.append(letters[li])
                li += 1
            di += 1
        else:
            out.append(ch)
    return "".join(out)


def _autokey_shift(plain_idx: int, key_idx: int, *, variant: str) -> int:
    if variant == "beaufort":
        return (key_idx - plain_idx) % 26
    return (plain_idx + key_idx) % 26


def _autokey_unshift(cipher_idx: int, key_idx: int, *, variant: str) -> int:
    if variant == "beaufort":
        return (key_idx - cipher_idx) % 26
    return (cipher_idx - key_idx) % 26


def autokey(
    text: str,
    key: str,
    *,
    variant: str = "standard",
    extension: str = "plaintext",
) -> str:
    """
    Autokey cipher (alphabetic priming key).

    - variant: ``standard`` (Vigenère addition) or ``beaufort`` (subtraction)
    - extension: ``plaintext`` (text-autokey) or ``ciphertext`` (key-autokey)
    """
    if extension not in {"plaintext", "ciphertext"}:
        raise ValueError("Autokey extension must be 'plaintext' or 'ciphertext'")
    key = clean_alpha(key)
    if not key:
        raise ValueError("Autokey key required")
    stream: list[str] = list(key)
    out: list[str] = []
    ai = 0
    for ch in text:
        if ch.isalpha():
            k = char_index(stream[ai])
            p = char_index(ch)
            ct_idx = _autokey_shift(p, k, variant=variant)
            ct_char = index_char(ct_idx, upper=ch.isupper())
            out.append(ct_char)
            if extension == "ciphertext":
                stream.append(index_char(ct_idx))
            else:
                stream.append(index_char(p))
            ai += 1
        else:
            out.append(ch)
    return "".join(out)


def autokey_decrypt(
    text: str,
    key: str,
    *,
    variant: str = "standard",
    extension: str = "plaintext",
) -> str:
    if extension not in {"plaintext", "ciphertext"}:
        raise ValueError("Autokey extension must be 'plaintext' or 'ciphertext'")
    key = clean_alpha(key)
    if not key:
        raise ValueError("Autokey key required")
    stream: list[str] = list(key)
    out: list[str] = []
    ai = 0
    for ch in text:
        if ch.isalpha():
            k = char_index(stream[ai])
            ct_idx = char_index(ch)
            plain_idx = _autokey_unshift(ct_idx, k, variant=variant)
            plain_char = index_char(plain_idx, upper=ch.isupper())
            out.append(plain_char)
            if extension == "ciphertext":
                stream.append(index_char(ct_idx))
            else:
                stream.append(index_char(plain_idx))
            ai += 1
        else:
            out.append(ch)
    return "".join(out)


def gronsfeld_autokey(
    text: str,
    numeric_key: str,
    *,
    extension: str = "plaintext",
    variant: str = "standard",
) -> str:
    """
    Gronsfeld autokey: numeric priming key, then plaintext/ciphertext extension.

    After the seed digits, each shift is ``char_index(letter) mod 10``.
    ``extension='ciphertext'`` uses prior ciphertext letters (ciphertext-autokey Gronsfeld).
    ``variant='beaufort'`` uses subtraction combiner.

    Not to be confused with Eyes GAK/XGAK (dynamic permutation ciphers in ``gak.py``).
    """
    if extension not in {"plaintext", "ciphertext"}:
        raise ValueError("Gronsfeld autokey extension must be 'plaintext' or 'ciphertext'")
    if variant not in {"standard", "beaufort"}:
        raise ValueError("Gronsfeld autokey variant must be 'standard' or 'beaufort'")
    if not numeric_key or not numeric_key.isdigit():
        raise ValueError("Gronsfeld autokey key must be numeric")
    stream: list[int] = [int(d) for d in numeric_key]
    out: list[str] = []
    ai = 0
    for ch in text:
        if ch.isalpha():
            k = stream[ai]
            p = char_index(ch)
            if variant == "beaufort":
                ct_idx = (k - p) % 26
            else:
                ct_idx = (p + k) % 26
            ct_char = index_char(ct_idx, upper=ch.isupper())
            out.append(ct_char)
            if extension == "ciphertext":
                stream.append(ct_idx % 10)
            else:
                stream.append(p % 10)
            ai += 1
        else:
            out.append(ch)
    return "".join(out)


def gronsfeld_autokey_decrypt(
    text: str,
    numeric_key: str,
    *,
    extension: str = "plaintext",
    variant: str = "standard",
) -> str:
    if extension not in {"plaintext", "ciphertext"}:
        raise ValueError("Gronsfeld autokey extension must be 'plaintext' or 'ciphertext'")
    if variant not in {"standard", "beaufort"}:
        raise ValueError("Gronsfeld autokey variant must be 'standard' or 'beaufort'")
    if not numeric_key or not numeric_key.isdigit():
        raise ValueError("Gronsfeld autokey key must be numeric")
    stream: list[int] = [int(d) for d in numeric_key]
    out: list[str] = []
    ai = 0
    for ch in text:
        if ch.isalpha():
            k = stream[ai]
            ct_idx = char_index(ch)
            if variant == "beaufort":
                plain_idx = (k - ct_idx) % 26
            else:
                plain_idx = (ct_idx - k) % 26
            plain_char = index_char(plain_idx, upper=ch.isupper())
            out.append(plain_char)
            if extension == "ciphertext":
                stream.append(ct_idx % 10)
            else:
                stream.append(plain_idx % 10)
            ai += 1
        else:
            out.append(ch)
    return "".join(out)


def _porta_transform(x: int, k: int) -> int:
    """Porta combiner; self-reciprocal."""
    k = k % 13
    if x < 13:
        return (x + k) % 13 + 13
    return (x - 13 - k) % 13


def porta_autokey(
    text: str,
    key: str,
    *,
    extension: str = "plaintext",
) -> str:
    """Porta cipher with alphabetic priming key and plaintext/ciphertext extension."""
    if extension not in {"plaintext", "ciphertext"}:
        raise ValueError("Porta autokey extension must be 'plaintext' or 'ciphertext'")
    key = clean_alpha(key)
    if not key:
        raise ValueError("Porta autokey key required")
    stream: list[str] = list(key)
    out: list[str] = []
    ai = 0
    for ch in text:
        if ch.isalpha():
            k = char_index(stream[ai]) % 13
            p = char_index(ch)
            ct_idx = _porta_transform(p, k)
            ct_char = index_char(ct_idx, upper=ch.isupper())
            out.append(ct_char)
            if extension == "ciphertext":
                stream.append(index_char(ct_idx))
            else:
                stream.append(index_char(p))
            ai += 1
        else:
            out.append(ch)
    return "".join(out)


def porta_autokey_decrypt(
    text: str,
    key: str,
    *,
    extension: str = "plaintext",
) -> str:
    if extension not in {"plaintext", "ciphertext"}:
        raise ValueError("Porta autokey extension must be 'plaintext' or 'ciphertext'")
    key = clean_alpha(key)
    if not key:
        raise ValueError("Porta autokey key required")
    stream: list[str] = list(key)
    out: list[str] = []
    ai = 0
    for ch in text:
        if ch.isalpha():
            k = char_index(stream[ai]) % 13
            ct_idx = char_index(ch)
            plain_idx = _porta_transform(ct_idx, k)
            plain_char = index_char(plain_idx, upper=ch.isupper())
            out.append(plain_char)
            if extension == "ciphertext":
                stream.append(index_char(ct_idx))
            else:
                stream.append(index_char(plain_idx))
            ai += 1
        else:
            out.append(ch)
    return "".join(out)


def xautokey(
    text: str,
    key: str,
    *,
    mode: str = "sum",
) -> str:
    """
    Additive X-autokey: after priming key, keystream index from lagged (p±c) mod 26.

    ``mode='sum'``: k_i = (p_{i-|K|} + c_{i-|K|}) mod 26
    ``mode='diff'``: k_i = (c_{i-|K|} - p_{i-|K|}) mod 26
    """
    if mode not in {"sum", "diff"}:
        raise ValueError("X-autokey mode must be 'sum' or 'diff'")
    key = clean_alpha(key)
    if not key:
        raise ValueError("X-autokey key required")
    seed_len = len(key)
    stream: list[str] = list(key)
    plain_hist: list[int] = []
    cipher_hist: list[int] = []
    out: list[str] = []
    ai = 0
    for ch in text:
        if ch.isalpha():
            if ai < seed_len:
                k = char_index(stream[ai])
            else:
                lag = ai - seed_len
                p_lag = plain_hist[lag]
                c_lag = cipher_hist[lag]
                k = (p_lag + c_lag) % 26 if mode == "sum" else (c_lag - p_lag) % 26
            p = char_index(ch)
            ct_idx = (p + k) % 26
            ct_char = index_char(ct_idx, upper=ch.isupper())
            out.append(ct_char)
            plain_hist.append(p)
            cipher_hist.append(ct_idx)
            ai += 1
        else:
            out.append(ch)
    return "".join(out)


def xautokey_decrypt(
    text: str,
    key: str,
    *,
    mode: str = "sum",
) -> str:
    if mode not in {"sum", "diff"}:
        raise ValueError("X-autokey mode must be 'sum' or 'diff'")
    key = clean_alpha(key)
    if not key:
        raise ValueError("X-autokey key required")
    seed_len = len(key)
    plain_hist: list[int] = []
    cipher_hist: list[int] = []
    out: list[str] = []
    ai = 0
    for ch in text:
        if ch.isalpha():
            if ai < seed_len:
                k = char_index(key[ai])
            else:
                lag = ai - seed_len
                p_lag = plain_hist[lag]
                c_lag = cipher_hist[lag]
                k = (p_lag + c_lag) % 26 if mode == "sum" else (c_lag - p_lag) % 26
            ct_idx = char_index(ch)
            plain_idx = (ct_idx - k) % 26
            plain_char = index_char(plain_idx, upper=ch.isupper())
            out.append(plain_char)
            plain_hist.append(plain_idx)
            cipher_hist.append(ct_idx)
            ai += 1
        else:
            out.append(ch)
    return "".join(out)


def nihilist_autokey(
    text: str,
    numeric_key: str,
    *,
    extension: str = "plaintext",
    polybius_key: str = "NIHILIST",
) -> str:
    """Nihilist with numeric priming stream extended by plaintext or ciphertext digits."""
    if extension not in {"plaintext", "ciphertext"}:
        raise ValueError("Nihilist autokey extension must be 'plaintext' or 'ciphertext'")
    if not numeric_key or not numeric_key.isdigit():
        raise ValueError("Nihilist autokey key must be numeric")
    from cipherops.ciphers.utils import build_polybius_square, polybius_coords

    square = build_polybius_square(polybius_key, size=5)
    stream: list[int] = [int(d) for d in numeric_key]
    digits: list[str] = []
    si = 0
    for ch in text:
        if ch.isalpha():
            r, c = polybius_coords(square, ch)
            d1, d2 = r + 1, c + 1
            k1 = stream[si]
            k2 = stream[si + 1]
            out1 = (d1 + k1) % 10
            out2 = (d2 + k2) % 10
            digits.append(str(out1))
            digits.append(str(out2))
            if extension == "ciphertext":
                stream.extend([out1, out2])
            else:
                stream.extend([d1 % 10, d2 % 10])
            si += 2
        else:
            digits.append(ch)
    return "".join(digits)


def nihilist_autokey_decrypt(
    text: str,
    numeric_key: str,
    *,
    extension: str = "plaintext",
    polybius_key: str = "NIHILIST",
) -> str:
    if extension not in {"plaintext", "ciphertext"}:
        raise ValueError("Nihilist autokey extension must be 'plaintext' or 'ciphertext'")
    if not numeric_key or not numeric_key.isdigit():
        raise ValueError("Nihilist autokey key must be numeric")
    from cipherops.ciphers.utils import build_polybius_square

    square = build_polybius_square(polybius_key, size=5)
    stream: list[int] = [int(d) for d in numeric_key]
    raw_digits = "".join(ch for ch in text if ch.isdigit())
    letters: list[str] = []
    si = 0
    for i in range(0, len(raw_digits), 2):
        d1 = int(raw_digits[i])
        d2 = int(raw_digits[i + 1])
        k1 = stream[si]
        k2 = stream[si + 1]
        r = (d1 - k1) % 10
        c = (d2 - k2) % 10
        if not 1 <= r <= 5 or not 1 <= c <= 5:
            raise ValueError(f"Invalid Polybius coordinates after decrypt: {r},{c}")
        letters.append(square[r - 1][c - 1])
        if extension == "ciphertext":
            stream.extend([d1, d2])
        else:
            stream.extend([r % 10, c % 10])
        si += 2
    out: list[str] = []
    li = 0
    di = 0
    for ch in text:
        if ch.isdigit():
            if di % 2 == 0:
                out.append(letters[li])
                li += 1
            di += 1
        else:
            out.append(ch)
    return "".join(out)


def _build_book_index(words: list[str]) -> list[tuple[int, int, str]]:
    """1-based (word, char, letter) tuples for coordinate book cipher."""
    index: list[tuple[int, int, str]] = []
    for wi, word in enumerate(words, start=1):
        for ci, letter in enumerate(word, start=1):
            if letter.isalpha():
                index.append((wi, ci, letter.upper()))
    return index


def book_cipher(text: str, words: list[str], *, start: int = 0) -> str:
    """
    Coordinate book cipher: each letter becomes ``word.char`` (1-indexed) into fixed word list.
    """
    index = _build_book_index(words)
    if not index:
        raise ValueError("Book word list required")
    coords: list[str] = []
    cursor = start % len(index)
    for ch in clean_alpha(text):
        target = ch.upper()
        found = False
        for offset in range(len(index)):
            pos = (cursor + offset) % len(index)
            wi, ci, letter = index[pos]
            if letter == target:
                coords.append(f"{wi}.{ci}")
                cursor = (pos + 1) % len(index)
                found = True
                break
        if not found:
            for pos, (wi, ci, letter) in enumerate(index):
                if letter == target:
                    coords.append(f"{wi}.{ci}")
                    cursor = (pos + 1) % len(index)
                    found = True
                    break
        if not found:
            coords.append("0.0")
    return " ".join(coords)


def book_cipher_decrypt(text: str, words: list[str]) -> str:
    index = _build_book_index(words)
    word_map: dict[tuple[int, int], str] = {(wi, ci): letter for wi, ci, letter in index}
    tokens = text.split()
    return "".join(word_map.get(_parse_coord(tok), "?") for tok in tokens)


def _parse_coord(token: str) -> tuple[int, int]:
    parts = token.split(".")
    if len(parts) != 2:
        return (0, 0)
    return int(parts[0]), int(parts[1])


def vernam(text: str, otp_key: str) -> str:
    """Manual one-time pad: mod-26 addition with non-repeating key, |K| >= |P|."""
    key = clean_alpha(otp_key)
    alpha = clean_alpha(text)
    if len(key) < len(alpha):
        raise ValueError("Vernam OTP key must be at least as long as plaintext")
    out: list[str] = []
    ki = 0
    for ch in text:
        if ch.isalpha():
            k = char_index(key[ki])
            out.append(index_char(char_index(ch) + k, upper=ch.isupper()))
            ki += 1
        else:
            out.append(ch)
    return "".join(out)


def vernam_decrypt(text: str, otp_key: str) -> str:
    key = clean_alpha(otp_key)
    out: list[str] = []
    ki = 0
    for ch in text:
        if ch.isalpha():
            k = char_index(key[ki])
            out.append(index_char(char_index(ch) - k, upper=ch.isupper()))
            ki += 1
        else:
            out.append(ch)
    return "".join(out)


def running_key(text: str, key_text: str) -> str:
    """Vigenere with non-repeating keystream from a long text."""
    key = clean_alpha(key_text)
    if len(key) < len(clean_alpha(text)):
        raise ValueError("Running key text must be at least as long as plaintext")
    return vigenere(text, key[: len(clean_alpha(text))])


def running_key_decrypt(text: str, key_text: str) -> str:
    key = clean_alpha(key_text)
    return vigenere_decrypt(text, key[: len(clean_alpha(text))])


def porta(text: str, key: str) -> str:
    """Porta cipher using the standard 13-alphabet reciprocal table."""
    key = clean_alpha(key)
    if not key:
        raise ValueError("Porta key required")
    out = []
    ki = 0
    for ch in text:
        if ch.isalpha():
            k = char_index(key[ki % len(key)]) % 13
            x = char_index(ch)
            if x < 13:
                y = (x + k) % 13 + 13
            else:
                y = (x - 13 - k) % 13
            out.append(index_char(y, upper=ch.isupper()))
            ki += 1
        else:
            out.append(ch)
    return "".join(out)


def simple_substitution(text: str, mapping: str) -> str:
    """Encrypt with a 26-letter substitution alphabet."""
    mapping = mapping.upper()
    if len(set(mapping)) != 26 or len(mapping) != 26:
        raise ValueError("Substitution mapping must be 26 unique letters")
    table = {plain: mapping[i] for i, plain in enumerate(ALPHABET)}
    out = []
    for ch in text:
        if ch.isalpha():
            mapped = table[ch.upper()]
            out.append(mapped if ch.isupper() else mapped.lower())
        else:
            out.append(ch)
    return "".join(out)


def simple_substitution_decrypt(text: str, mapping: str) -> str:
    mapping = mapping.upper()
    inverse = {mapping[i]: ALPHABET[i] for i in range(26)}
    out = []
    for ch in text:
        if ch.isalpha():
            mapped = inverse[ch.upper()]
            out.append(mapped if ch.isupper() else mapped.lower())
        else:
            out.append(ch)
    return "".join(out)


def homophonic_substitution(text: str, mapping: dict[str, str]) -> str:
    """
    Homophonic cipher: each plaintext letter maps to one chosen homophone.
    mapping example: {'A': '01', 'B': '12', ...}
    """
    out = []
    for ch in text:
        if ch.isalpha():
            out.append(mapping.get(ch.upper(), ch.upper()))
        else:
            out.append(ch)
    return "".join(out)


def homophonic_substitution_decrypt(text: str, inverse: dict[str, str]) -> str:
    digits = "".join(ch for ch in text if ch.isdigit())
    out = []
    i = 0
    while i < len(digits):
        token = digits[i : i + 2]
        if token in inverse:
            out.append(inverse[token])
            i += 2
        elif digits[i] in inverse:
            out.append(inverse[digits[i]])
            i += 1
        else:
            i += 1
    return "".join(out)


def baconian_encode(text: str, *, a_char: str = "A", b_char: str = "B") -> str:
    """Encode letters to Bacon biliteral groups (5 bits each)."""
    bacon_map = {
        "A": "AAAAA",
        "B": "AAAAB",
        "C": "AAABA",
        "D": "AAABB",
        "E": "AABAA",
        "F": "AABAB",
        "G": "AABBA",
        "H": "AABBB",
        "I": "ABAAA",
        "J": "ABAAB",
        "K": "ABABA",
        "L": "ABABB",
        "M": "ABBAA",
        "N": "ABBAB",
        "O": "ABBBA",
        "P": "ABBBB",
        "Q": "BAAAA",
        "R": "BAAAB",
        "S": "BAABA",
        "T": "BAABB",
        "U": "BABAA",
        "V": "BABAB",
        "W": "BABBA",
        "X": "BABBB",
        "Y": "BBAAA",
        "Z": "BBAAB",
    }
    return "".join(
        bacon_map[ch.upper()].replace("A", a_char).replace("B", b_char)
        for ch in clean_alpha(text)
    )


def baconian_decode(text: str, *, a_char: str = "A", b_char: str = "B") -> str:
    inverse = {
        "AAAAA": "A",
        "AAAAB": "B",
        "AAABA": "C",
        "AAABB": "D",
        "AABAA": "E",
        "AABAB": "F",
        "AABBA": "G",
        "AABBB": "H",
        "ABAAA": "I",
        "ABAAB": "J",
        "ABABA": "K",
        "ABABB": "L",
        "ABBAA": "M",
        "ABBAB": "N",
        "ABBBA": "O",
        "ABBBB": "P",
        "BAAAA": "Q",
        "BAAAB": "R",
        "BAABA": "S",
        "BAABB": "T",
        "BABAA": "U",
        "BABAB": "V",
        "BABBA": "W",
        "BABBB": "X",
        "BBAAA": "Y",
        "BBAAB": "Z",
    }
    normalized = text.upper().replace(a_char.upper(), "A").replace(b_char.upper(), "B")
    normalized = "".join(ch for ch in normalized if ch in "AB")
    return "".join(inverse[normalized[i : i + 5]] for i in range(0, len(normalized), 5))


def polybius_square(text: str, key: str = "") -> str:
    """Map letters to row/column digit pairs (1-indexed)."""
    from cipherops.ciphers.utils import build_polybius_square, polybius_coords

    square = build_polybius_square(key, size=5)
    pairs = []
    for ch in clean_alpha(text):
        r, c = polybius_coords(square, ch)
        pairs.append(f"{r + 1}{c + 1}")
    return " ".join(pairs)


def polybius_square_decrypt(text: str, key: str = "") -> str:
    from cipherops.ciphers.utils import build_polybius_square

    square = build_polybius_square(key, size=5)
    digits = "".join(ch for ch in text if ch.isdigit())
    out = []
    for i in range(0, len(digits), 2):
        r = int(digits[i]) - 1
        c = int(digits[i + 1]) - 1
        out.append(square[r][c])
    return "".join(out)


def nomenclator_encode(text: str, codebook: dict[str, str]) -> str:
    """Encode words/phrases using a nomenclator codebook."""
    words = text.split()
    return " ".join(codebook.get(word.upper(), word) for word in words)


def nomenclator_decode(text: str, codebook: dict[str, str]) -> str:
    inverse = {v: k for k, v in codebook.items()}
    tokens = text.split()
    return " ".join(inverse.get(token, token) for token in tokens)
