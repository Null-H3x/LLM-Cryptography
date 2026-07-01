"""Validated cipher registry linking math docs, implementations, and datasets."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from cipherops.ciphers import classical, encoding, fractionated, polygraphic, transposition


@dataclass(frozen=True)
class CipherSpec:
    family: str
    slug: str
    encrypt: Callable[..., str]
    decrypt: Callable[..., str]
    params: dict
    math_ref: str
    difficulty: int
    variants: tuple[str, ...] = ()


PLAIN_SAMPLES = [
    "The quick brown fox jumps over the lazy dog.",
    "Cryptography is the practice and study of techniques for secure communication.",
    "Security is not a product, but a process.",
    "Never trust anyone who says they have absolute security.",
    "The art of war is of vital importance to the state.",
    "All that we see or seem is but a dream within a dream.",
    "To be or not to be, that is the question.",
    "It was the best of times, it was the worst of times.",
    "In the beginning the Universe was created.",
    "Data is the new oil, but encryption is the refinery.",
]

DEFAULT_SUBSTITUTION = "QWERTYUIOPASDFGHJKLZXCVBNM"
DEFAULT_HOMOPHONIC = {
    "A": "01",
    "B": "02",
    "C": "03",
    "D": "04",
    "E": "05",
    "F": "06",
    "G": "07",
    "H": "08",
    "I": "09",
    "J": "10",
    "K": "11",
    "L": "12",
    "M": "13",
    "N": "14",
    "O": "15",
    "P": "16",
    "Q": "17",
    "R": "18",
    "S": "19",
    "T": "20",
    "U": "21",
    "V": "22",
    "W": "23",
    "X": "24",
    "Y": "25",
    "Z": "26",
}
HOMOPHONIC_ALTERNATES = {
    "E": ["05", "27", "28", "29"],
    "T": ["20", "30", "31"],
    "A": ["01", "32"],
    "O": ["15", "33"],
    "I": ["09", "34"],
    "N": ["14", "35"],
    "R": ["18", "36"],
    "S": ["19", "37"],
}
HOMOPHONIC_INVERSE = {code: letter for letter, code in DEFAULT_HOMOPHONIC.items()}
for letter, codes in HOMOPHONIC_ALTERNATES.items():
    for code in codes:
        HOMOPHONIC_INVERSE[code] = letter
NOMENCLATOR = {
    "ATTACK": "142",
    "AT": "17",
    "DAWN": "88",
    "THE": "9",
    "ENEMY": "55",
    "IS": "3",
    "NEAR": "61",
}
RUNNING_KEY_TEXT = (
    "CONFIDENTIALITY INTEGRITY AND AVAILABILITY ARE THE CORE PRINCIPLES OF MODERN "
    "INFORMATION SECURITY PRACTICE FOR ORGANIZATIONS WORLDWIDE TODAY ALWAYS"
)


def _registry() -> list[CipherSpec]:
    return [
        CipherSpec("atbash", "atbash", classical.atbash, classical.atbash, {}, "docs/math-formulas/atbash.md", 1),
        CipherSpec("caesar", "caesar-rot13", lambda t: classical.caesar(t, 13), lambda t: classical.caesar(t, -13), {"shift": 13}, "docs/math-formulas/caesar.md", 1),
        CipherSpec("caesar", "caesar-rot3", lambda t: classical.caesar(t, 3), lambda t: classical.caesar(t, -3), {"shift": 3}, "docs/math-formulas/caesar.md", 1),
        CipherSpec("affine", "affine-a2b5", lambda t: classical.affine(t, 5, 8), lambda t: classical.affine_decrypt(t, 5, 8), {"a": 5, "b": 8}, "docs/math-formulas/affine.md", 3),
        CipherSpec("railfence", "railfence-3", lambda t: transposition.rail_fence(t, 3), lambda t: transposition.rail_fence_decrypt(t, 3), {"rails": 3}, "docs/math-formulas/railfence.md", 2),
        CipherSpec("baconian", "baconian-ab", classical.baconian_encode, classical.baconian_decode, {"a_char": "A", "b_char": "B"}, "docs/math-formulas/baconian.md", 2),
        CipherSpec("polybius", "polybius-square", lambda t: classical.polybius_square(t, "CRYPTO"), lambda t: classical.polybius_square_decrypt(t, "CRYPTO"), {"key": "CRYPTO"}, "docs/math-formulas/polybius.md", 2),
        CipherSpec("substitution", "substitution-qwerty", lambda t: classical.simple_substitution(t, DEFAULT_SUBSTITUTION), lambda t: classical.simple_substitution_decrypt(t, DEFAULT_SUBSTITUTION), {"mapping": DEFAULT_SUBSTITUTION}, "docs/math-formulas/substitution.md", 3),
        CipherSpec("nomenclator", "nomenclator-basic", lambda t: classical.nomenclator_encode(t, NOMENCLATOR), lambda t: classical.nomenclator_decode(t, NOMENCLATOR), {"codebook": NOMENCLATOR}, "docs/math-formulas/nomenclator.md", 3),
        CipherSpec("columnar", "columnar-keyword", lambda t: transposition.columnar_transposition(t, "KEYWORD"), lambda t: transposition.columnar_transposition_decrypt(t, "KEYWORD"), {"key": "KEYWORD"}, "docs/math-formulas/columnar.md", 3),
        CipherSpec("autokey", "autokey-standard", lambda t: classical.autokey(t, "KEY"), lambda t: classical.autokey_decrypt(t, "KEY"), {"key": "KEY", "variant": "standard"}, "docs/math-formulas/autokey.md", 4, ("standard",)),
        CipherSpec("autokey", "autokey-beaufort", lambda t: classical.autokey(t, "KEY", variant="beaufort"), lambda t: classical.autokey_decrypt(t, "KEY", variant="beaufort"), {"key": "KEY", "variant": "beaufort"}, "docs/math-formulas/autokey.md", 4, ("beaufort",)),
        CipherSpec("beaufort", "beaufort-keyword", lambda t: classical.beaufort(t, "KEY"), lambda t: classical.beaufort(t, "KEY"), {"key": "KEY"}, "docs/math-formulas/beaufort.md", 3),
        CipherSpec("porta", "porta-keyword", lambda t: classical.porta(t, "KEY"), lambda t: classical.porta(t, "KEY"), {"key": "KEY"}, "docs/math-formulas/porta.md", 4),
        CipherSpec("running_key", "running-key-book", lambda t: classical.running_key(t, RUNNING_KEY_TEXT), lambda t: classical.running_key_decrypt(t, RUNNING_KEY_TEXT), {"key_source": "book-excerpt"}, "docs/math-formulas/running-key.md", 4),
        CipherSpec("vigenere", "vigenere-keyword", lambda t: classical.vigenere(t, "KEY"), lambda t: classical.vigenere_decrypt(t, "KEY"), {"key": "KEY"}, "docs/math-formulas/vigenere.md", 3),
        CipherSpec("gronsfeld", "gronsfeld-31415", lambda t: classical.gronsfeld(t, "31415"), lambda t: classical.gronsfeld_decrypt(t, "31415"), {"numeric_key": "31415"}, "docs/math-formulas/gronsfeld.md", 3),
        CipherSpec("homophonic", "homophonic-basic", lambda t: classical.homophonic_substitution(t, DEFAULT_HOMOPHONIC), lambda t: classical.homophonic_substitution_decrypt(t, HOMOPHONIC_INVERSE), {"mapping": "basic-english"}, "docs/math-formulas/homophonic.md", 4),
        CipherSpec("four_square", "four-square-keys", lambda t: polygraphic.four_square(t, "KEYONE", "KEYTWO"), lambda t: polygraphic.four_square(t, "KEYONE", "KEYTWO", decrypt=True), {"key1": "KEYONE", "key2": "KEYTWO"}, "docs/math-formulas/four-square.md", 4),
        CipherSpec("hill", "hill-2x2", lambda t: polygraphic.hill(t, [[3, 3], [2, 5]]), lambda t: polygraphic.hill(t, [[3, 3], [2, 5]], decrypt=True), {"matrix": [[3, 3], [2, 5]]}, "docs/math-formulas/hill.md", 4),
        CipherSpec("playfair", "playfair-keyword", lambda t: polygraphic.playfair(t, "KEYWORD"), lambda t: polygraphic.playfair(t, "KEYWORD", decrypt=True), {"key": "KEYWORD"}, "docs/math-formulas/playfair.md", 3),
        CipherSpec("adfgvx", "adfgvx-keys", lambda t: fractionated.adfgvx(t, "SECRET", "PRIVATE"), lambda t: fractionated.adfgvx_decrypt(t, "SECRET", "PRIVATE"), {"polybius_key": "SECRET", "transposition_key": "PRIVATE"}, "docs/math-formulas/adfgvx.md", 5),
        CipherSpec("adfgx", "adfgx-keys", lambda t: fractionated.adfgx(t, "SECRET", "PRIVATE"), lambda t: fractionated.adfgx_decrypt(t, "SECRET", "PRIVATE"), {"polybius_key": "SECRET", "transposition_key": "PRIVATE"}, "docs/math-formulas/adfgx.md", 5),
        CipherSpec("bifid", "bifid-keyword", lambda t: fractionated.bifid(t, "KEYWORD"), lambda t: fractionated.bifid_decrypt(t, "KEYWORD"), {"key": "KEYWORD"}, "docs/math-formulas/bifid.md", 4),
        CipherSpec("straddle_checkerboard", "straddle-default", fractionated.straddle_checkerboard, fractionated.straddle_checkerboard_decrypt, {"layout": "default"}, "docs/math-formulas/straddle-checkerboard.md", 5),
        CipherSpec("trifid", "trifid-keyword", lambda t: fractionated.trifid(t, "KEYWORD"), lambda t: fractionated.trifid_decrypt(t, "KEYWORD"), {"key": "KEYWORD"}, "docs/math-formulas/trifid.md", 5),
        CipherSpec("base64", "b64", encoding.base64_encode, encoding.base64_decode, {}, "docs/math-formulas/base64.md", 1),
        CipherSpec("fractionated_morse", "fractionated-morse", lambda t: fractionated.fractionated_morse(t, "CIPHER"), lambda t: fractionated.fractionated_morse_decrypt(t, "CIPHER"), {"substitution_key": "CIPHER"}, "docs/math-formulas/fractionated-morse.md", 5),
    ]


CIPHER_REGISTRY: list[CipherSpec] = _registry()


def get_cipher(slug: str) -> CipherSpec:
    for spec in CIPHER_REGISTRY:
        if spec.slug == slug:
            return spec
    raise KeyError(f"Unknown cipher slug: {slug}")
