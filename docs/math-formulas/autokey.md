# Autokey Cipher

## Mathematical Definition

Polyalphabetic cipher where the keystream is **primed** by a short key, then **extended with plaintext** (standard) or uses Beaufort subtraction (beaufort variant).

**Keystream (standard, plaintext-autokey):**

\[
k_i = \begin{cases}
K_i & i < |K| \\
p_{i-|K|} & i \geq |K|
\end{cases}
\]

**Encryption (standard Vigenère-style):**

\[
E(p_i) = (p_i + k_i) \mod 26
\]

**Beaufort variant:**

\[
E(p_i) = (k_i - p_i) \mod 26
\]

**Decryption** recovers \(p_i\) from \(c_i\), then appends \(p_i\) to the keystream for subsequent positions.

### Variants in this repo

| Slug | Variant | Keystream extension |
|------|---------|---------------------|
| `autokey-standard` | Plaintext-autokey | \(k_i \leftarrow p_{i-|K|}\) after seed |
| `autokey-beaufort` | Beaufort autokey | Same keystream, subtract combiner |

### Not implemented: ciphertext-autokey

Some historical sources extend the keystream with **prior ciphertext** instead of plaintext:

\[
k_i = \begin{cases} K_i & i < |K| \\ c_{i-|K|} & i \geq |K| \end{cases}
\]

That variant is documented here for completeness but **not** in `cipherops/ciphers/classical.py`. Do not assume plaintext-autokey formulas apply to ciphertext-autokey without verification.

---

## Cryptanalysis

Autokey is **not periodic**. Do **not** apply Vigenère period recovery (Kasiski, Friedman, coset IC) — those tools are misleading for long messages.

### Regimes

| Regime | Condition | IC behavior | Practical attack |
|--------|-----------|-------------|------------------|
| **Seed-dominated** | \(n \leq |K|\) | Low IC, polyalphabetic-like | Brute-force \(26^{|K|}\) seed |
| **Mixed** | \(|K| < n \leq 2|K|\) | Transitional | Seed brute force + prefix scoring |
| **OTP-like** | \(n \gg |K|\) | IC → English (~0.067) | Ciphertext-only intractable; use cribs/KPT |

Where \(n = |C|\) (alphabetic length), \(|K|\) = priming key length.

### Known-plaintext attack (most powerful)

Once any plaintext character \(p_j\) is known, the keystream extends:

\[
k_{j+|K|} = p_j \quad\text{(standard plaintext-autokey)}
\]

Decrypt left-to-right: each recovered \(p_i\) feeds \(k_{i+|K|}\). A crib of length \(|K|\) at the start recovers the full seed and unlocks the message.

### What does **not** work

- Kasiski examination for period \(|K|\) (repeats reflect plaintext structure, not key period)
- Friedman key-length estimate (often ≈ 1 on long ciphertext)
- Coset IC at period \(|K|\) (no stable column structure)
- Per-column Caesar shift recovery (MIC) as for Vigenère

### Keyspace

| Attack model | \|K\| |
|--------------|-------|
| Priming seed only | \(26^{|K|}\) |
| Full message, ciphertext-only | \(26^n\) (OTP-like) |
| With known plaintext / crib | Iterative; polynomial in message length |

See [`../cryptanalysis/non-periodic-polyalphabetic.md`](../cryptanalysis/non-periodic-polyalphabetic.md) and [`../cryptanalysis/keyspace-reference.md`](../cryptanalysis/keyspace-reference.md).

---

## Python Implementation

See `cipherops/ciphers/classical.py::autokey`, `autokey_decrypt`.

Property profiles set `analysis_guidance.periodicity = non_periodic` and omit `coset_ic`.

---

## Dataset

- `datasets/fingerprinted/autokey-standard/data.jsonl`
- `datasets/fingerprinted/autokey-beaufort/data.jsonl`

## References

- Standard treatment: Vigenère autokey (plaintext feedback)
- Cross-check: [`../cryptanalysis/curated-sources.md`](../cryptanalysis/curated-sources.md)
