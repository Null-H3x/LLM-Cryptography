"""Shared helpers for random-test corpus generation and validation."""

from __future__ import annotations

import random
import re
import string
from typing import Any

from cipherops.ciphers.registry import (
    BOOK_CIPHER_WORDS,
    CIPHER_REGISTRY,
    NOMENCLATOR,
    RUNNING_KEY_TEXT,
    VERNAM_OTP_KEY,
)
from cipherops.ciphers.utils import clean_alpha, sha256_text

DEFAULT_SEED = 7689
SAMPLES_PER_CIPHER = 3

RANDOM_TEST_ROOT_NAME = "random test"

ADJECTIVES = (
    "quick",
    "silent",
    "hidden",
    "ancient",
    "random",
    "secure",
    "broken",
    "clever",
    "nested",
    "unknown",
)
NOUNS = (
    "cipher",
    "message",
    "keyword",
    "signal",
    "pattern",
    "keystream",
    "artifact",
    "oracle",
    "channel",
    "payload",
)
VERBS = ("moves", "reveals", "protects", "breaks", "encodes", "decodes", "hides", "maps")
OBJECTS = ("state", "vault", "field", "matrix", "stream", "archive", "network", "grid")

# Ciphers whose ciphertext includes per-run entropy (timestamp, OAEP padding, etc.)
NON_DETERMINISTIC = {"fernet", "rsa-oaep-hybrid"}

# Families that need short alpha plaintext bounded by fixed demo keys.
KEY_BOUNDED_SLUGS = {
    "vernam-otp-demo": len(clean_alpha(VERNAM_OTP_KEY)) - 8,
    "running-key-book": len(clean_alpha(RUNNING_KEY_TEXT)) - 8,
}

# Slugs marked encrypt_only in registry but that still have decrypt implementations.
ENCRYPT_ONLY_SLUGS = {spec.slug for spec in CIPHER_REGISTRY if spec.encrypt_only}

# Classifier soft-match aliases (expected family -> acceptable top-hit families).
FAMILY_ALIASES: dict[str, set[str]] = {
    "gak": {"gak", "xgak", "substitution", "vigenere", "autokey"},
    "gronsfeld_autokey": {"gronsfeld_autokey", "autokey", "gronsfeld", "vigenere", "nihilist_autokey"},
    "porta_autokey": {"porta_autokey", "autokey", "porta", "vigenere"},
    "nihilist_autokey": {"nihilist_autokey", "nihilist", "autokey", "gronsfeld_autokey"},
    "xautokey": {"xautokey", "autokey", "vigenere"},
    "base64": {"base64", "hex", "encoding"},
    "hex": {"hex", "base64", "encoding"},
    "pam5": {"pam5", "encoding"},
    "manchester": {"manchester", "encoding", "binary"},
    "fractionated_morse": {"fractionated_morse", "bifid", "polybius", "adfgx"},
    "homophonic": {"homophonic", "substitution", "nihilist"},
    "book_cipher": {"book_cipher", "substitution", "unknown"},
    "ed25519": {"ed25519", "encoding", "hex", "base64"},
    "x25519": {"x25519", "encoding", "hex", "base64"},
    "rsa": {"rsa", "encoding", "base64", "hex"},
}


def plaintext_style(spec) -> str:
    if spec.slug in KEY_BOUNDED_SLUGS or spec.family == "book_cipher":
        return "key_bounded"
    if spec.family == "nomenclator":
        return "nomenclator"
    if spec.family in {"base64", "hex", "pam5", "manchester"}:
        return "utf8_sentence"
    if spec.family in {"sha256", "sha512", "sha3_256", "blake2b", "hmac"}:
        return "utf8_sentence"
    if spec.family in {"playfair", "four_square", "hill"}:
        return "alpha_sentence"
    return "sentence"


def _random_sentence(rng: random.Random, *, min_alpha: int = 24) -> str:
    while True:
        text = (
            f"The {rng.choice(ADJECTIVES)} {rng.choice(NOUNS)} {rng.choice(VERBS)} "
            f"over the {rng.choice(OBJECTS)} while agents relay field data."
        )
        if len(clean_alpha(text)) >= min_alpha:
            return text


def _random_alpha_sentence(rng: random.Random, *, max_alpha: int | None = None, min_alpha: int = 20) -> str:
    while True:
        words = [rng.choice(NOUNS).upper() for _ in range(rng.randint(4, 8))]
        text = " ".join(words)
        alpha_len = len(clean_alpha(text))
        if alpha_len < min_alpha:
            continue
        if max_alpha is not None and alpha_len > max_alpha:
            text = " ".join(words[: max(2, len(words) // 2)])
            alpha_len = len(clean_alpha(text))
        if max_alpha is None or alpha_len <= max_alpha:
            return text


def _random_nomenclator(rng: random.Random) -> str:
    codes = list(NOMENCLATOR.keys())
    parts = [rng.choice(codes), rng.choice(codes)]
    if rng.random() < 0.5:
        parts.append(rng.choice(NOUNS).upper())
    return " ".join(parts)


def _random_book_plaintext(rng: random.Random) -> str:
    words = [w for w in BOOK_CIPHER_WORDS if any(c.isalpha() for c in w)]
    picks = [rng.choice(words) for _ in range(rng.randint(3, 6))]
    return " ".join(picks)


def generate_plaintext(spec, rng: random.Random, sample_index: int) -> str:
    style = plaintext_style(spec)
    if style == "key_bounded":
        cap = KEY_BOUNDED_SLUGS.get(spec.slug, 48)
        return _random_alpha_sentence(rng, max_alpha=cap, min_alpha=min(12, cap))
    if style == "nomenclator":
        return _random_nomenclator(rng)
    if style == "book_cipher" or spec.family == "book_cipher":
        return _random_book_plaintext(rng)
    if style == "utf8_sentence":
        extra = "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(4))
        return _random_sentence(rng) + f" Token={extra}."
    if style == "alpha_sentence":
        return _random_alpha_sentence(rng)
    # Default sentence; vary length slightly per sample.
    text = _random_sentence(rng, min_alpha=18 + sample_index * 4)
    if sample_index == 2 and rng.random() < 0.4:
        text = text.replace("agents", "AGENTS").upper()
    return text


def build_record(spec, plaintext: str, sample_index: int, *, seed: int) -> dict[str, Any]:
    return {
        "id": f"{spec.slug}-r{sample_index:02d}",
        "slug": spec.slug,
        "cipher_family": spec.family,
        "params": spec.params,
        "math_ref": spec.math_ref,
        "era": spec.era,
        "difficulty": spec.difficulty,
        "plaintext": plaintext,
        "plaintext_sha256": sha256_text(plaintext),
        "encrypt_only": spec.encrypt_only,
        "variants": list(spec.variants),
        "generation": {
            "seed": seed,
            "sample_index": sample_index,
            "plaintext_style": plaintext_style(spec),
        },
    }


def family_match(expected: str, hypothesis_family: str) -> bool:
    expected_norm = expected.replace("-", "_")
    got_norm = hypothesis_family.replace("-", "_")
    if expected_norm == got_norm:
        return True
    aliases = FAMILY_ALIASES.get(expected_norm, set())
    return got_norm in aliases or expected_norm in aliases


def serialize_ciphertext(value: str | list | dict) -> str | list:
    """JSON-safe ciphertext for corpus storage."""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return value
    return str(value)


def is_list_ciphertext(value: Any) -> bool:
    return isinstance(value, list) and bool(value) and isinstance(value[0], int)
