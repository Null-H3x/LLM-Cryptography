"""Unified decrypt / brute dispatch for stream-extension cipher families."""

from __future__ import annotations

from typing import Any

from cipherops.ciphers.classical import (
    autokey_decrypt,
    gronsfeld_autokey_decrypt,
    nihilist_autokey_decrypt,
    porta_autokey_decrypt,
    xautokey_decrypt,
)
from cipherops.ciphers.utils import clean_alpha


STREAM_FAMILIES = frozenset(
    {
        "autokey",
        "gronsfeld_autokey",
        "porta_autokey",
        "xautokey",
        "nihilist_autokey",
    }
)


def stream_decrypt(
    ciphertext: str,
    seed: str,
    *,
    family: str = "autokey",
    variant: str = "standard",
    extension: str = "plaintext",
    mode: str = "sum",
) -> str:
    """Decrypt under a stream-extension family using the registry implementations."""
    family_norm = family.replace("-", "_")
    if family_norm == "gronsfeld_autokey":
        return gronsfeld_autokey_decrypt(ciphertext, seed, extension=extension, variant=variant)
    if family_norm == "porta_autokey":
        return porta_autokey_decrypt(ciphertext, seed, extension=extension)
    if family_norm == "xautokey":
        return xautokey_decrypt(ciphertext, seed, mode=mode, extension=extension)
    if family_norm == "nihilist_autokey":
        return nihilist_autokey_decrypt(ciphertext, seed, extension=extension)
    return autokey_decrypt(ciphertext, seed, variant=variant, extension=extension)


def stream_family_from_slug(slug: str) -> str:
    if slug.startswith("gronsfeld-autokey"):
        return "gronsfeld_autokey"
    if slug.startswith("porta-autokey"):
        return "porta_autokey"
    if slug.startswith("xautokey"):
        return "xautokey"
    if slug.startswith("nihilist-autokey"):
        return "nihilist_autokey"
    return "autokey"


def hypothesis_from_slug(slug: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build stream-extension hypothesis defaults from a fingerprinted slug."""
    params = dict(params or {})
    family = stream_family_from_slug(slug)
    hyp: dict[str, Any] = {"family": family}
    if family == "autokey":
        hyp["variant"] = params.get("variant", "standard")
        hyp["extension"] = params.get("extension", "plaintext")
        key = params.get("key", "KEY")
        hyp["seed"] = str(key)
        hyp["seed_length"] = len(clean_alpha(str(key))) or 3
    elif family == "gronsfeld_autokey":
        hyp["extension"] = params.get("extension", "plaintext")
        hyp["variant"] = params.get("variant", "standard")
        nk = str(params.get("numeric_key", "31415"))
        hyp["seed"] = nk
        hyp["seed_length"] = len(nk)
    elif family == "porta_autokey":
        hyp["extension"] = params.get("extension", "plaintext")
        key = params.get("key", "KEY")
        hyp["seed"] = str(key)
        hyp["seed_length"] = len(clean_alpha(str(key))) or 3
    elif family == "xautokey":
        hyp["mode"] = params.get("mode", "sum")
        hyp["extension"] = params.get("extension", "plaintext")
        key = params.get("key", "KEY")
        hyp["seed"] = str(key)
        hyp["seed_length"] = len(clean_alpha(str(key))) or 3
    elif family == "nihilist_autokey":
        hyp["extension"] = params.get("extension", "plaintext")
        nk = str(params.get("numeric_key", "31415"))
        hyp["seed"] = nk
        hyp["seed_length"] = len(nk)
    return hyp


def is_alpha_stream_family(family: str) -> bool:
    """True when ciphertext is expected to be alphabetic (not digit-space nihilist CT-ext)."""
    family_norm = family.replace("-", "_")
    if family_norm == "nihilist_autokey":
        ext = "plaintext"
        return True
    return family_norm in STREAM_FAMILIES
