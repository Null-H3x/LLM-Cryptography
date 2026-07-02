"""External / book keystream constraint propagation (running key, Vernam)."""

from __future__ import annotations

from cipherops.analysis.external_keystream_solver import (
    EXTERNAL_CORPORA,
    search_running_key_offsets,
    verify_vernam_key_length,
)
from cipherops.ciphers.utils import char_index, clean_alpha, index_char
from cipherops.constraints.domain import (
    ConstraintState,
    FindingKind,
    FindingsMap,
    Pin,
    coerce_symbol,
    plaintext_as_ints,
)


def propagate_external_keystream(state: ConstraintState) -> FindingsMap:
    """
    Propagate constraints for non-repeating external keystreams.

    Model: ``C[t] = (P[t] + K[t]) mod 26`` where ``K`` is drawn from a fixed corpus
    at hypothesis offset (running key) or supplied OTP material (Vernam).

    Hypothesis keys:
    - ``family``: ``running_key`` | ``vernam`` | ``book_cipher``
    - ``corpus``: corpus id (default ``running-key-book``)
    - ``key_offset``: int slide into corpus
    - ``otp_key``: Vernam key material (optional)
    - ``brute_top_n``: corpus offset search breadth
    """
    if not state.ciphertext:
        raise ValueError("external_keystream propagator requires state.ciphertext")

    family = str(state.hypothesis.get("family", "running_key")).replace("-", "_")
    corpus = str(state.hypothesis.get("corpus", "running-key-book"))
    offset = int(state.hypothesis.get("key_offset", 0))

    out = FindingsMap(
        meta={
            "propagator": "external_keystream",
            "family": family,
            "corpus": corpus,
            "key_offset": offset,
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

    if family == "vernam":
        otp = state.hypothesis.get("otp_key") or EXTERNAL_CORPORA.get(corpus, "")
        check = verify_vernam_key_length(state.ciphertext, str(otp))
        out.meta["vernam_length"] = check
        if not check["length_ok"]:
            out.add(
                FindingKind.CONFLICT,
                "vernam_length",
                "hard",
                **check,
            )

    # Stream pins: at each known pt, derive K[t] = C[t] - P[t]
    for i, p in enumerate(pt_ints):
        if p is None or i >= len(ct_ints):
            continue
        k_val = (ct_ints[i] - p) % 26
        out.add(
            FindingKind.STREAM_PIN,
            "crib",
            "hard",
            stream_index=i,
            value=k_val,
            role="external_keystream",
            note="Non-repeating K[t] at absolute position",
        )

    top_n = state.hypothesis.get("brute_top_n")
    if top_n and family == "running_key":
        hits = search_running_key_offsets(
            state.ciphertext,
            corpus_key=corpus,
            top_n=int(top_n),
        )
        for rank, hit in enumerate(hits):
            out.add(
                FindingKind.SEED_CANDIDATE,
                "corpus_search",
                "heuristic",
                key_offset=hit["offset"],
                score=hit["score"],
                rank=rank,
                corpus=corpus,
                plaintext_preview=hit.get("plaintext_preview"),
            )
            if rank == 0 and hit.get("score", 0) >= 0.4:
                out.add(
                    FindingKind.ASSIGNMENT,
                    "corpus_search",
                    "heuristic",
                    field="key_offset",
                    value=hit["offset"],
                    score=hit["score"],
                )

    return out
