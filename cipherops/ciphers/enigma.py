"""3-rotor Enigma M3 (teaching model, pycipher-compatible wiring)."""

from __future__ import annotations

from cipherops.ciphers.utils import clean_alpha

ROTOR_WIRINGS = (
    "EKMFLGDQVZNTOWYHXUSPAIBRCJ",
    "AJDKSIRUXBLHWTMCQGZNPYFVOE",
    "BDFHJLCPRTXVZNYEIWGAKMUSQO",
)
INV_ROTOR_WIRINGS = (
    "UWYGADFPVZBECKMTHXSLRINQOJ",
    "AJPCZWRLFBDKOTYUQGENHXMIVS",
    "TAGBPCSDQEUFVNZHYIXJWLRKOM",
)
REFLECTOR_B = "YRUHQSLDPXNGOKMIEBFZCWVJAT"
NOTCHES = (("Q",), ("E",), ("V",))
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def _a2i(ch: str) -> int:
    return ord(ch.upper()) - ord("A")


def _subst(ch: str, key: str, *, offset: int = 0) -> str:
    return key[(_a2i(ch) + offset) % 26]


def _apply_steckers(ch: str, pairs: list[tuple[str, str]]) -> str:
    for a, b in pairs:
        if ch == a:
            return b
        if ch == b:
            return a
    return ch


def _apply_rotor(ch: str, offset: int, wiring: str) -> str:
    ch = _subst(ch, wiring, offset=offset)
    return _subst(ch, ALPHABET, offset=-offset)


def _advance(settings: list[str]) -> None:
    if settings[1] in NOTCHES[1]:
        settings[0] = _subst(settings[0], ALPHABET, offset=1)
        settings[1] = _subst(settings[1], ALPHABET, offset=1)
    if settings[2] in NOTCHES[2]:
        settings[1] = _subst(settings[1], ALPHABET, offset=1)
    settings[2] = _subst(settings[2], ALPHABET, offset=1)


def _encipher_char(
    ch: str,
    settings: list[str],
    rings: tuple[str, str, str],
    *,
    plugboard_pairs: list[tuple[str, str]],
) -> str:
    _advance(settings)
    ch = _apply_steckers(ch, plugboard_pairs)
    for i in (2, 1, 0):
        offset = ord(settings[i]) - ord(rings[i])
        ch = _apply_rotor(ch, offset, ROTOR_WIRINGS[i])
    ch = _subst(ch, REFLECTOR_B)
    for i in (0, 1, 2):
        offset = ord(settings[i]) - ord(rings[i])
        ch = _apply_rotor(ch, offset, INV_ROTOR_WIRINGS[i])
    return _apply_steckers(ch, plugboard_pairs)


def enigma(
    text: str,
    *,
    settings: tuple[str, str, str] = ("A", "A", "A"),
    rings: tuple[str, str, str] = ("A", "A", "A"),
    plugboard_pairs: list[tuple[str, str]] | None = None,
) -> str:
    """Encrypt/decrypt A–Z under rotors I/II/III and reflector B (self-reciprocal)."""
    pairs = plugboard_pairs or []
    rotor_settings = list(settings)
    out: list[str] = []
    ai = 0
    alpha = clean_alpha(text)
    for ch in text:
        if ch.isalpha():
            enc = _encipher_char(alpha[ai], rotor_settings, rings, plugboard_pairs=pairs)
            out.append(enc if ch.isupper() else enc.lower())
            ai += 1
        else:
            out.append(ch)
    return "".join(out)


def enigma_decrypt(
    text: str,
    *,
    settings: tuple[str, str, str] = ("A", "A", "A"),
    rings: tuple[str, str, str] = ("A", "A", "A"),
    plugboard_pairs: list[tuple[str, str]] | None = None,
) -> str:
    return enigma(text, settings=settings, rings=rings, plugboard_pairs=plugboard_pairs)
