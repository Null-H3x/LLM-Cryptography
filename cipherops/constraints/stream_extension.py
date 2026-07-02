"""Autokey / stream-extension constraint propagation."""

from __future__ import annotations

from cipherops.analysis.autokey_solver import (
    brute_force_autokey_seed,
    brute_force_gronsfeld_autokey_seed,
)
from cipherops.analysis.stream_cipher import STREAM_FAMILIES, stream_decrypt
from cipherops.ciphers.utils import char_index, clean_alpha, index_char
from cipherops.constraints.domain import (
    ConstraintState,
    FindingKind,
    FindingsMap,
    Pin,
    coerce_symbol,
    plaintext_as_ints,
)


def _stream_index_for_autokey(
    i: int,
    seed_len: int,
    pt: list[int],
    ct: list[int],
    *,
    extension: str,
) -> int | None:
    """Return keystream symbol index used at alpha position ``i`` (0-based)."""
    if i < seed_len:
        return None
    lag = i - seed_len
    if extension == "plaintext":
        return pt[lag]
    return ct[lag]


def _brute_stream_seed(
    ciphertext: str,
    seed_len: int,
    *,
    family: str,
    variant: str,
    extension: str,
    mode: str,
    top_n: int,
) -> list[dict]:
    family_norm = family.replace("-", "_")
    if family_norm == "gronsfeld_autokey":
        return brute_force_gronsfeld_autokey_seed(ciphertext, seed_len, extension=extension, top_n=top_n)
    if family_norm in {"porta_autokey", "xautokey", "nihilist_autokey"}:
        # Generic column: enumerate small seeds where applicable
        if family_norm == "nihilist_autokey":
            return brute_force_gronsfeld_autokey_seed(ciphertext, seed_len, extension=extension, top_n=top_n)
        return brute_force_autokey_seed(
            ciphertext, seed_len, variant=variant, extension=extension, top_n=top_n
        )
    return brute_force_autokey_seed(
        ciphertext, seed_len, variant=variant, extension=extension, top_n=top_n
    )


def propagate_stream_extension(state: ConstraintState) -> FindingsMap:
    """
    Propagate plaintext/ciphertext-autokey stream constraints from cribs and partial plaintext.

    Hypothesis keys:
    - ``family``: ``autokey`` | ``gronsfeld_autokey`` | ``porta_autokey`` | ``xautokey`` | ``nihilist_autokey``
    - ``variant``: ``standard`` | ``beaufort`` (autokey / gronsfeld autokey)
    - ``extension``: ``plaintext`` | ``ciphertext``
    - ``mode``: ``sum`` | ``diff`` (xautokey)
    - ``seed_length``: int (required for stream derivation)
    - ``brute_top_n``: if set with short seed, emit ``seed_candidate`` heuristics
    """
    if not state.ciphertext:
        raise ValueError("stream_extension propagator requires state.ciphertext")

    family = str(state.hypothesis.get("family", "autokey")).replace("-", "_")
    variant = state.hypothesis.get("variant", "standard")
    extension = state.hypothesis.get("extension", "plaintext")
    mode = state.hypothesis.get("mode", "sum")
    seed_len = int(state.hypothesis.get("seed_length", 3))

    if family == "nihilist_autokey" and extension == "ciphertext":
        ct_stripped = clean_alpha(state.ciphertext)
        if not ct_stripped and any(ch.isdigit() for ch in state.ciphertext):
            raise ValueError(
                "nihilist_autokey ciphertext extension uses digit-space ciphertext; "
                "use alpha nihilist-autokey variant or peel encoding first"
            )

    out = FindingsMap(
        meta={
            "propagator": "stream_extension",
            "family": family,
            "variant": variant,
            "extension": extension,
            "mode": mode,
            "seed_length": seed_len,
        }
    )

    ct_alpha = clean_alpha(state.ciphertext)
    if not ct_alpha:
        raise ValueError("stream_extension requires alphabetic ciphertext")
    ct_ints = [char_index(ch) for ch in ct_alpha]

    pt_ints = plaintext_as_ints(state.plaintext_trial)
    if pt_ints is None:
        pt_ints = [None] * len(ct_ints)  # type: ignore[list-item]

    for pin in state.pins:
        if pin.pt is not None:
            pos = pin.pos
            if 0 <= pos < len(pt_ints):
                pt_ints[pos] = coerce_symbol(pin.pt)
                out.add(
                    FindingKind.ASSIGNMENT,
                    "crib",
                    "hard",
                    pos=pos,
                    field="pt",
                    value=pt_ints[pos],
                )

    for i, p in enumerate(pt_ints):
        if p is None:
            continue
        if i < seed_len:
            out.add(
                FindingKind.STREAM_PIN,
                "crib",
                "hard",
                stream_index=i,
                value=p,
                role="seed",
            )
        elif extension == "plaintext":
            stream_at = i
            source_pos = i - seed_len
            if pt_ints[source_pos] is not None:
                out.add(
                    FindingKind.STREAM_PIN,
                    "pt_extension",
                    "propagated",
                    stream_index=stream_at,
                    value=pt_ints[source_pos],
                    source_pt_pos=source_pos,
                )
        else:
            if i < len(ct_ints):
                out.add(
                    FindingKind.STREAM_PIN,
                    "ct_extension",
                    "propagated",
                    stream_index=i,
                    value=ct_ints[i],
                    note="Ciphertext-autokey extends with prior ciphertext letter index",
                )

    if pt_ints and all(p is not None for p in pt_ints):
        plain_str = "".join(index_char(p) for p in pt_ints)
        declared_seed = state.hypothesis.get("seed")
        verified_seed: str | None = None
        try:
            if declared_seed:
                dec = stream_decrypt(
                    state.ciphertext,
                    str(declared_seed),
                    family=family,
                    variant=variant,
                    extension=extension,
                    mode=mode,
                )
                if clean_alpha(dec) == plain_str:
                    verified_seed = str(declared_seed)
            elif family in STREAM_FAMILIES and seed_len <= 6:
                hits = _brute_stream_seed(
                    state.ciphertext,
                    seed_len,
                    family=family,
                    variant=variant,
                    extension=extension,
                    mode=mode,
                    top_n=1,
                )
                if hits and clean_alpha(hits[0]["plaintext"]) == plain_str:
                    verified_seed = hits[0]["seed"]

            if verified_seed:
                out.add(
                    FindingKind.ASSIGNMENT,
                    "full_decrypt",
                    "hard",
                    field="seed",
                    value=verified_seed,
                )
            elif declared_seed or family in STREAM_FAMILIES:
                out.add(
                    FindingKind.CONFLICT,
                    "full_decrypt",
                    "hard",
                    expected=plain_str,
                    declared_seed=declared_seed,
                )
        except ValueError as exc:
            out.add(FindingKind.CONFLICT, "full_decrypt", "hard", error=str(exc))

    top_n = state.hypothesis.get("brute_top_n")
    if top_n and seed_len <= 6 and family in STREAM_FAMILIES:
        hits = _brute_stream_seed(
            state.ciphertext,
            seed_len,
            family=family,
            variant=variant,
            extension=extension,
            mode=mode,
            top_n=int(top_n),
        )
        for rank, hit in enumerate(hits):
            out.add(
                FindingKind.SEED_CANDIDATE,
                "brute_force",
                "heuristic",
                seed=hit["seed"],
                score=hit["score"],
                rank=rank,
            )

    return out


def propagate_from_crib_prefix(
    ciphertext: str,
    crib: str,
    *,
    seed_length: int = 3,
    variant: str = "standard",
    extension: str = "plaintext",
    seed: str | None = None,
    family: str = "autokey",
) -> FindingsMap:
    """Convenience: pin plaintext crib at positions 0..|crib|-1 and propagate."""
    from cipherops.constraints.domain import AlphabetDomain

    pins = [Pin(pos=i, pt=ch) for i, ch in enumerate(clean_alpha(crib))]
    hypothesis: dict = {
        "family": family,
        "variant": variant,
        "extension": extension,
        "seed_length": seed_length,
    }
    if seed is not None:
        hypothesis["seed"] = seed
    state = ConstraintState(
        domain=AlphabetDomain(size=26, name="latin"),
        hypothesis=hypothesis,
        ciphertext=ciphertext,
        pins=pins,
        plaintext_trial=crib,
    )
    return propagate_stream_extension(state)
