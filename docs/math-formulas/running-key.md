# Running Key Cipher

## Mathematical Definition

Vigenère-style encryption with a **non-repeating** keystream drawn from a long external text (book, article, page):

\[
E_{i}(p_i) = (p_i + k_i) \mod 26, \quad k_i = \text{BookKey}_i, \quad |K| \geq |P|
\]

Unlike Vigenère, the keystream **never repeats** within the message. Unlike autokey, the keystream does **not** depend on plaintext — it depends on an external corpus.

---

## Cryptanalysis

Running key is **non-periodic**. Kasiski, Friedman, and coset IC do **not** apply.

### Attack surface

| Method | Viability | Notes |
|--------|-----------|-------|
| **Book crib** | High | Long matching plaintext reveals source and offset |
| **Corpus search** | Medium | Scan candidate books at all offsets; score with n-grams |
| **Brute force 26^m** | Not viable | Key is not a short repeating alphabet string |
| **Dictionary / source ID** | High | Stylometry and word-frequency match to candidate texts |

### Security factors

- **Key reuse** across messages → depth attack (same as Vigenère reuse, but without period)
- **Predictable sources** (common books, Bible, newspapers) shrink search space dramatically
- **Short messages** with unknown book → hard; long messages with crib → often broken

### Keyspace

| Model | Search space |
|-------|--------------|
| Known book, unknown offset | \(O(n)\) alignments |
| Unknown book from fixed corpus | corpus size × offsets |
| Unknown book, no corpus | Open-ended literary search |

See [`../cryptanalysis/non-periodic-polyalphabetic.md`](../cryptanalysis/non-periodic-polyalphabetic.md).

---

## Python Implementation

See `cipherops/ciphers/classical.py::running_key`, `running_key_decrypt`.

Dataset uses a fixed book excerpt (`RUNNING_KEY_TEXT` in registry).

Property profiles: `analysis_guidance.periodicity = non_periodic`, `coset_ic = null`.

---

## Dataset

Validated examples: `datasets/fingerprinted/running-key-book/data.jsonl`
