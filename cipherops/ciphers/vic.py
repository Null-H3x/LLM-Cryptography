"""VIC cipher — straddle checkerboard + chain addition + transposition."""

from __future__ import annotations

from cipherops.ciphers.fractionated import straddle_checkerboard, straddle_checkerboard_decrypt
from cipherops.ciphers.transposition import columnar_transposition, columnar_transposition_decrypt


def _chain_add_digits(digits: str, numeric_key: str) -> str:
    """Non-carrying mod-10 addition per digit (VIC chain addition step)."""
    if not numeric_key or not numeric_key.isdigit():
        raise ValueError("VIC chain key must be numeric")
    key = numeric_key
    out: list[str] = []
    for i, d in enumerate(digits):
        if not d.isdigit():
            continue
        k = int(key[i % len(key)])
        out.append(str((int(d) + k) % 10))
    return "".join(out)


def _chain_subtract_digits(digits: str, numeric_key: str) -> str:
    if not numeric_key or not numeric_key.isdigit():
        raise ValueError("VIC chain key must be numeric")
    key = numeric_key
    out: list[str] = []
    for i, d in enumerate(digits):
        if not d.isdigit():
            continue
        k = int(key[i % len(key)])
        out.append(str((int(d) - k) % 10))
    return "".join(out)


def vic_encrypt(
    text: str,
    *,
    chain_key: str = "31415",
    transposition_key: str = "PRIVATE",
) -> str:
    """
    Teaching VIC pipeline: straddle checkerboard → chain addition mod 10 → columnar transposition.
    """
    digits = straddle_checkerboard(text)
    chained = _chain_add_digits(digits, chain_key)
    return columnar_transposition(chained, transposition_key)


def vic_decrypt(
    text: str,
    *,
    chain_key: str = "31415",
    transposition_key: str = "PRIVATE",
) -> str:
    untransposed = columnar_transposition_decrypt(text, transposition_key)
    digits = _chain_subtract_digits(untransposed, chain_key)
    return straddle_checkerboard_decrypt(digits)
