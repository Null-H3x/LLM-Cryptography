# Noita Eye Messages (Unsolved Corpus)

## Problem Statement

Nine ciphertext messages from the Noita game eye puzzle, sourced from
[noita-eyes.neocities.org](https://noita-eyes.neocities.org/) and maintained in
the [Eyes](https://github.com/Null-H3x/Eyes) repository. **Plaintext is unknown**
— this is an active unsolved cryptanalysis target, not a validated reversible cipher.

## Alphabet and Encoding

- Deck size **N = 83**; each symbol is an integer in `[0, 82]`.
- Raw community data uses **base-5 trigrams** (three digits per symbol); the canonical
  integer deck representation lives in `datasets/unsolved/noita-eye-messages/corpus.json`.

## Messages

| Label | Length | Notes |
|-------|--------|-------|
| East 1 | 99 | |
| West 1 | 103 | |
| East 2 | 118 | |
| West 2 | 102 | |
| East 3 | 137 | longest message |
| West 3 | 124 | |
| East 4 | 119 | |
| West 4 | 120 | |
| East 5 | 114 | no West 5 pair |

**Total:** 1036 ciphertext symbols across 9 messages.

## Observed Structure (Validated)

1. **Universal header anomaly:** `CT[1] = 66` and `CT[2] = 5` in every message.
   Under a shared position-indexed keystream, identical ciphertext at the same
   position implies identical plaintext — a built-in crib.
2. **In-depth alignment:** identical ciphertext runs appear at identical absolute
   positions across messages (e.g. positions 1–24 agree on East 1 / West 1 / East 2).
3. **Flat unigram:** index of coincidence is near uniform (~0.012), ruling out simple
   monoalphabetic substitution or transposition of a language-like distribution.

## Leading Cryptanalytic Model

The Eyes `noita_eye_core` analysis supports a **polyalphabetic cipher with a
message-independent, position-indexed keystream** shared by all nine messages
(in depth). Under modular addition (Vigenère-style combiner):

```
C_i[t] = (P_i[t] + K[t]) mod N
```

Differencing cancels the keystream:

```
C_i[t] - C_j[t] ≡ P_i[t] - P_j[t]   (mod N)
```

Equivalent formulations include Beaufort/subtraction combiners; the key property
is that **K[t] depends only on absolute position t**, not on message identity.

### Ruled Out (from corpus structure)

| Family | Status |
|--------|--------|
| Monoalphabetic substitution | Refuted (too-flat unigram) |
| Simple transposition | Refuted (same reason) |
| Periodic Vigenère (short key) | Refuted (no coset-IoC lift) |
| Per-message autokey / running key | Refuted (incompatible with cross-message depth) |
| Per-message one-time pad | Refuted (column coincidence) |

### Active Attack Surface

- **Crib-drag** exploiting universal headers and shared runs
- **N-way depth** / multi-ciphertext Vigenère at each column
- **PRNG keystream** hypotheses (Noita `NollaPRNG` / Park–Miller variants)
- **Base-5 trigram** coordinate/fractionation tests

## Dataset Location

```
datasets/unsolved/noita-eye-messages/
├── corpus.json      # full 9-message source (from Eyes)
├── data.jsonl       # one JSONL record per message (plaintext: null)
└── raw-base5.txt    # optional raw trigram export
```

Regenerate from upstream:

```bash
PYTHONPATH=. python3 scripts/import_eyes_corpus.py --clone
# or from a local Eyes checkout:
PYTHONPATH=. python3 scripts/import_eyes_corpus.py --source /path/to/Eyes
```

## References

- Eyes repository: https://github.com/Null-H3x/Eyes
- Corpus module: `noita_eye_core/corpus.py`
- Classifier verdict: `polyalphabetic_shared_keystream` (see `noita_eye_core/classify.py`)
