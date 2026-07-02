"""Periodic repeating-key constraint propagation (Vigenère-class)."""

from __future__ import annotations

from cipherops.analysis.periodic_solver import (
    PERIODIC_FAMILIES,
    _decrypt_periodic,
    brute_force_periodic_multi,
    recover_period_candidates,
)
from cipherops.ciphers.utils import char_index, clean_alpha, index_char
from cipherops.constraints.domain import (
    ConstraintState,
    FindingKind,
    FindingsMap,
    coerce_symbol,
    plaintext_as_ints,
)


def _keystream_symbol(ct: int, pt: int, *, family: str) -> int:
    family_norm = family.replace("-", "_")
    if family_norm == "beaufort":
        return (pt - ct) % 26
    return (ct - pt) % 26


def propagate_periodic_key(state: ConstraintState) -> FindingsMap:
    """
    Propagate constraints for periodic polyalphabetic keystreams.

    Model: ``C[t] = combiner(P[t], K[t mod period])`` with repeating key.

    Hypothesis keys:
    - ``family``: ``vigenere`` | ``beaufort`` | ``porta`` | ``gronsfeld``
    - ``period``: int key length (optional — inferred from coset IC)
    - ``key``: repeating key string (optional)
    - ``brute_top_n``: emit ``seed_candidate`` heuristics
    """
    if not state.ciphertext:
        raise ValueError("periodic_key propagator requires state.ciphertext")

    family = str(state.hypothesis.get("family", "vigenere")).replace("-", "_")
    if family not in PERIODIC_FAMILIES:
        family = "vigenere"

    period = int(state.hypothesis.get("period") or 0)
    if period < 2:
        candidates = recover_period_candidates(state.ciphertext)
        period = candidates[0] if candidates else 3

    out = FindingsMap(
        meta={
            "propagator": "periodic_key",
            "family": family,
            "period": period,
        }
    )

    ct_alpha = clean_alpha(state.ciphertext)
    ct_ints = [char_index(ch) for ch in ct_alpha]
    pt_ints = plaintext_as_ints(state.plaintext_trial)
    if pt_ints is None:
        pt_ints = [None] * len(ct_ints)  # type: ignore[list-item]

    for pin in state.pins:
        if pin.pt is not None and 0 <= pin.pos < len(pt_ints):
            pt_ints[pin.pos] = coerce_symbol(pin.pt)
            out.add(
                FindingKind.ASSIGNMENT,
                "crib",
                "hard",
                pos=pin.pos,
                field="pt",
                value=pt_ints[pin.pos],
            )

    # Derive key-symbol pins from known plaintext
    key_symbols: dict[int, int] = {}
    for i, p in enumerate(pt_ints):
        if p is None or i >= len(ct_ints):
            continue
        col = i % period
        k_sym = _keystream_symbol(ct_ints[i], p, family=family)
        if col in key_symbols and key_symbols[col] != k_sym:
            out.add(
                FindingKind.CONFLICT,
                "key_column",
                "hard",
                column=col,
                values=[key_symbols[col], k_sym],
                pos=i,
            )
        else:
            key_symbols[col] = k_sym
            out.add(
                FindingKind.STREAM_PIN,
                "crib",
                "hard",
                stream_index=col,
                pos=i,
                value=k_sym,
                role="key_column",
            )

    declared_key = state.hypothesis.get("key")
    if declared_key and pt_ints and all(p is not None for p in pt_ints):
        plain_str = "".join(index_char(p) for p in pt_ints)
        dec = _decrypt_periodic(state.ciphertext, str(declared_key), family=family)
        if clean_alpha(dec) == plain_str:
            out.add(
                FindingKind.ASSIGNMENT,
                "full_decrypt",
                "hard",
                field="key",
                value=str(declared_key),
            )
        else:
            out.add(FindingKind.CONFLICT, "full_decrypt", "hard", expected=plain_str, key=declared_key)

    top_n = state.hypothesis.get("brute_top_n")
    if top_n:
        hits = brute_force_periodic_multi(
            state.ciphertext,
            family=family,
            max_period=min(12, period + 3),
            top_n=int(top_n),
        )
        for rank, hit in enumerate(hits):
            out.add(
                FindingKind.SEED_CANDIDATE,
                "brute_force",
                "heuristic",
                key=hit["key"],
                period=hit["period"],
                score=hit["score"],
                rank=rank,
                family=family,
            )

    return out
