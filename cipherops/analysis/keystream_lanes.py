"""Catalog of keystream models and workflow routing metadata."""

from __future__ import annotations

from typing import Any, Literal

PropagatorName = Literal[
    "shared_keystream",
    "stream_extension",
    "dynamic_perm",
    "periodic_key",
    "external_keystream",
]

KeystreamModel = dict[str, Any]

KEYSTREAM_MODELS: list[KeystreamModel] = [
    {
        "id": "shared_depth",
        "label": "Shared position-indexed keystream",
        "propagator": "shared_keystream",
        "periodicity": "non_periodic",
        "symbol_class": "integer",
        "formula": "C_i[t] = combiner(P_i[t], K[t]) mod N",
        "families": ["noita_shared_keystream", "shared_keystream", "vernam_reuse"],
        "examples": ["Noita eye messages (mod 83)", "Multi-message integer decks"],
    },
    {
        "id": "stream_extension",
        "label": "Autokey / ciphertext-autokey extension",
        "propagator": "stream_extension",
        "periodicity": "non_periodic",
        "symbol_class": "alpha",
        "formula": "K extends with plaintext or prior ciphertext after seed",
        "families": [
            "autokey",
            "gronsfeld_autokey",
            "porta_autokey",
            "xautokey",
            "nihilist_autokey",
        ],
        "examples": ["autokey-standard", "porta-autokey-ciphertext", "nihilist-autokey-31415"],
    },
    {
        "id": "dynamic_perm",
        "label": "GAK / XGAK dynamic permutation",
        "propagator": "dynamic_perm",
        "periodicity": "non_periodic",
        "symbol_class": "alpha",
        "formula": "ct = active[pt]; active updated via PRNG permutations",
        "families": ["gak", "xgak"],
        "examples": ["gak-ctak-right-s42", "xgak-sum-left-s42"],
    },
    {
        "id": "periodic_polyalphabetic",
        "label": "Periodic repeating key",
        "propagator": "periodic_key",
        "periodicity": "periodic",
        "symbol_class": "alpha",
        "formula": "C[t] = combiner(P[t], K[t mod period]) mod 26",
        "families": ["vigenere", "beaufort", "porta", "gronsfeld"],
        "examples": ["vigenere-keyword", "beaufort-keyword", "gronsfeld-31415"],
    },
    {
        "id": "external_keystream",
        "label": "External / book keystream",
        "propagator": "external_keystream",
        "periodicity": "non_periodic",
        "symbol_class": "alpha",
        "formula": "C[t] = (P[t] + K[t]) mod 26; K from corpus offset",
        "families": ["running_key", "vernam", "book_cipher"],
        "examples": ["running-key-book", "vernam-otp-demo"],
    },
]

PROPAGATOR_BY_FAMILY: dict[str, str] = {}
for model in KEYSTREAM_MODELS:
    prop = model["propagator"]
    for fam in model["families"]:
        PROPAGATOR_BY_FAMILY[fam.replace("-", "_")] = prop


def list_keystream_models() -> list[dict[str, Any]]:
    """Return catalog for dashboard / API."""
    return [dict(m) for m in KEYSTREAM_MODELS]


def propagator_for_family(family: str) -> PropagatorName | None:
    fam = family.replace("-", "_")
    prop = PROPAGATOR_BY_FAMILY.get(fam)
    if prop in {
        "shared_keystream",
        "stream_extension",
        "dynamic_perm",
        "periodic_key",
        "external_keystream",
    }:
        return prop  # type: ignore[return-value]
    return None


def default_hypothesis(family: str) -> dict[str, Any]:
    fam = family.replace("-", "_")
    if fam in {"vigenere", "beaufort", "porta", "gronsfeld"}:
        return {"family": fam, "period": 3, "brute_top_n": 5}
    if fam in {"running_key", "book_cipher"}:
        return {"family": "running_key", "corpus": "running-key-book", "brute_top_n": 5}
    if fam == "vernam":
        return {"family": "vernam", "corpus": "running-key-book"}
    if fam in {"autokey", "gronsfeld_autokey", "porta_autokey", "xautokey", "nihilist_autokey"}:
        return {"family": fam, "seed_length": 3, "extension": "plaintext", "variant": "standard"}
    if fam in {"gak", "xgak"}:
        return {"mode": "ctak_right", "prng_seed": 42, "alphabet_size": 26}
    if fam in {"shared_keystream", "noita_shared_keystream"}:
        return {"combiner": "add", "family": "shared_keystream"}
    return {"family": fam}
