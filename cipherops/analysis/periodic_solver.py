"""Periodic polyalphabetic keystream recovery (Vigenère-class)."""

from __future__ import annotations

from cipherops.analysis.autokey_solver import _english_score
from cipherops.analysis.coset_ic import coset_ic_profile
from cipherops.ciphers.classical import (
    beaufort,
    gronsfeld,
    gronsfeld_decrypt,
    porta,
    vigenere_decrypt,
)
from cipherops.ciphers.utils import char_index, clean_alpha, index_char


PERIODIC_FAMILIES = frozenset({"vigenere", "beaufort", "porta", "gronsfeld"})


def _decrypt_periodic(
    ciphertext: str,
    key: str,
    *,
    family: str = "vigenere",
) -> str:
    family_norm = family.replace("-", "_")
    if family_norm == "beaufort":
        return beaufort(ciphertext, key)
    if family_norm == "porta":
        return porta(ciphertext, key)
    if family_norm == "gronsfeld":
        return gronsfeld_decrypt(ciphertext, key)
    return vigenere_decrypt(ciphertext, key)


def recover_period_candidates(ciphertext: str, *, max_period: int = 20) -> list[int]:
    """Rank likely key periods from coset IC."""
    profile = coset_ic_profile(ciphertext, max_period=max_period)
    by_period = profile.get("by_period") or {}
    if not by_period:
        return list(range(2, min(7, max_period + 1)))
    ranked = sorted(by_period.items(), key=lambda kv: kv[1], reverse=True)
    out: list[int] = []
    for period_str, ic in ranked[:6]:
        period = int(period_str)
        if period >= 2 and ic >= 0.055:
            out.append(period)
    if not out:
        out = [int(ranked[0][0])] if ranked else [3]
    return out


def brute_force_periodic_key(
    ciphertext: str,
    period: int,
    *,
    family: str = "vigenere",
    top_n: int = 5,
) -> list[dict]:
    """
    Recover repeating key of given period by column-wise Caesar shift scoring.

    Uses English unigram score on full decrypt as objective.
    """
    if period < 1 or period > 12:
        raise ValueError("period must be 1–12 for column brute")
    ct = clean_alpha(ciphertext)
    if len(ct) < period * 2:
        raise ValueError("ciphertext too short for period")

    ct_ints = [char_index(ch) for ch in ct]
    key_shifts: list[int] = []
    family_norm = family.replace("-", "_")

    for col in range(period):
        column = ct_ints[col::period]
        best_shift, best_score = 0, float("-inf")
        shift_range = range(10) if family_norm == "gronsfeld" else range(26)
        for shift in shift_range:
            if family_norm == "gronsfeld":
                plain_col = [index_char(c - shift) for c in column]
            else:
                plain_col = [index_char(c - shift) for c in column]
            score = _english_score("".join(plain_col))
            if score > best_score:
                best_score, best_shift = score, shift
        if family_norm == "gronsfeld":
            key_shifts.append(best_shift)
        else:
            key_shifts.append(best_shift)

    if family_norm == "gronsfeld":
        key = "".join(str(s) for s in key_shifts)
    else:
        key = "".join(index_char(s) for s in key_shifts)
    plain = _decrypt_periodic(ciphertext, key, family=family)
    score = _english_score(plain)
    return [
        {
            "period": period,
            "key": key,
            "family": family,
            "plaintext": plain,
            "score": round(score, 4),
            "hypothesis_patch": {"period": period, "key": key, "family": family},
        }
    ]


def brute_force_periodic_multi(
    ciphertext: str,
    *,
    family: str = "vigenere",
    max_period: int = 12,
    top_n: int = 5,
) -> list[dict]:
    """Try top coset-IC periods and return best key candidates."""
    results: list[dict] = []
    for period in recover_period_candidates(ciphertext, max_period=max_period):
        try:
            results.extend(brute_force_periodic_key(ciphertext, period, family=family, top_n=1))
        except ValueError:
            continue
    results.sort(key=lambda r: r["score"], reverse=True)
    return results[:top_n]
