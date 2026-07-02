"""External / book keystream search (running key, Vernam-style non-repeating key)."""

from __future__ import annotations

from cipherops.analysis.autokey_solver import _english_score
from cipherops.ciphers.classical import running_key_decrypt, vernam_decrypt
from cipherops.ciphers.registry import BOOK_CIPHER_WORDS, RUNNING_KEY_TEXT
from cipherops.ciphers.utils import clean_alpha


EXTERNAL_CORPORA: dict[str, str] = {
    "running-key-book": RUNNING_KEY_TEXT,
    "book-cipher-excerpt": " ".join(BOOK_CIPHER_WORDS),
}


def search_running_key_offsets(
    ciphertext: str,
    *,
    corpus_key: str = "running-key-book",
    max_offset: int | None = None,
    top_n: int = 5,
) -> list[dict]:
    """
    Slide a fixed external keystream across ciphertext; score decrypts by English unigrams.

    Model: C[t] = (P[t] + K[offset+t]) mod 26 with non-repeating K from corpus.
    """
    ct = clean_alpha(ciphertext)
    if len(ct) < 8:
        raise ValueError("ciphertext too short for running-key search")

    corpus = EXTERNAL_CORPORA.get(corpus_key)
    if not corpus:
        raise ValueError(f"Unknown corpus: {corpus_key}")
    key = clean_alpha(corpus)
    if len(key) < len(ct):
        raise ValueError("corpus shorter than ciphertext")

    limit = max_offset if max_offset is not None else max(0, len(key) - len(ct))
    limit = min(limit, 2000)
    results: list[dict] = []

    for offset in range(limit + 1):
        segment = key[offset : offset + len(ct)]
        if len(segment) < len(ct):
            break
        try:
            plain = running_key_decrypt(ciphertext, segment)
        except ValueError:
            continue
        score = _english_score(plain)
        results.append(
            {
                "offset": offset,
                "corpus": corpus_key,
                "score": round(score, 4),
                "plaintext_preview": plain[:120],
                "plaintext": plain,
                "hypothesis_patch": {
                    "family": "running_key",
                    "key_offset": offset,
                    "corpus": corpus_key,
                },
            }
        )

    results.sort(key=lambda r: r["score"], reverse=True)
    return results[:top_n]


def verify_vernam_key_length(ciphertext: str, key_material: str) -> dict:
    """Check Vernam OTP length constraint |K| >= |P| for alpha ciphertext."""
    ct_len = len(clean_alpha(ciphertext))
    key_len = len(clean_alpha(key_material))
    return {
        "ciphertext_alpha_len": ct_len,
        "key_alpha_len": key_len,
        "length_ok": key_len >= ct_len,
        "family": "vernam",
    }
