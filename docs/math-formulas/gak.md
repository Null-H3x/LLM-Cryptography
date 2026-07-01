# GAK — Gronsfeld AutoKey

## Definition

**GAK** (Gronsfeld AutoKey) combines Gronsfeld digit shifts with plaintext-autokey keystream extension.

**Priming key:** numeric string \(K = d_0 d_1 \ldots d_{m-1}\), each \(d_j \in \{0,\ldots,9\}\).

**Keystream shifts** \(s_i\):

\[
s_i = \begin{cases}
d_i & i < m \\
p_{i-m} \bmod 10 & i \geq m
\end{cases}
\]

where \(p_j\) is the alphabetic index (A=0) of plaintext letter \(j\).

**Encryption:**

\[
E(p_i) = (p_i + s_i) \mod 26
\]

## Properties

| Property | Value |
|----------|-------|
| Periodicity | **Non-periodic** |
| Seed keyspace | \(10^m\) |
| Shift alphabet | Digits 0–9 (Gronsfeld) |
| Extension | Plaintext feedback (text-autokey) |

Do **not** apply Kasiski / Friedman / coset IC as for periodic Vigenère or Gronsfeld.

## Cryptanalysis

Same regime model as alphabetic autokey ([`autokey.md`](autokey.md)):

| Regime | Condition | Attack |
|--------|-----------|--------|
| Seed-dominated | \(n \leq m\) | Brute \(10^m\) numeric seed |
| Mixed | \(m < n \leq 2m\) | Seed brute + prefix scoring |
| OTP-like | \(n \gg m\) | Cribs / known plaintext |

Known plaintext at position \(j\) fixes \(s_{j+m} = p_j \bmod 10\).

## Python Implementation

`cipherops/ciphers/classical.py::gronsfeld_autokey`, `gronsfeld_autokey_decrypt`

## Dataset

`datasets/fingerprinted/gak-31415/data.jsonl`

## See also

- [`xgak.md`](xgak.md) — ciphertext-autokey Gronsfeld variant
- [`gronsfeld.md`](gronsfeld.md) — periodic numeric-key Vigenère
- [`../cryptanalysis/non-periodic-polyalphabetic.md`](../cryptanalysis/non-periodic-polyalphabetic.md)
