# XGAK — eXtended Gronsfeld AutoKey (ciphertext-autokey)

## Definition

**XGAK** extends GAK with **ciphertext-autokey** (key-autokey) feedback: after the numeric priming seed, each shift derives from the **prior ciphertext** letter, not plaintext.

**Keystream shifts** \(s_i\):

\[
s_i = \begin{cases}
d_i & i < m \\
c_{i-m} \bmod 10 & i \geq m
\end{cases}
\]

**Encryption:**

\[
E(p_i) = (p_i + s_i) \mod 26
\]

## vs GAK

| | GAK | XGAK |
|---|-----|------|
| Extension source | Plaintext \(p_{i-m}\) | Ciphertext \(c_{i-m}\) |
| Decrypt dependency | Sequential; each \(p_i\) feeds forward | Sequential; each \(c_i\) feeds forward |
| Error propagation | Wrong seed poisons body | Single decrypt error poisons all following shifts |
| Receiver needs | Priming key only | Priming key + ciphertext (already available) |

Both are **non-periodic** — periodic polyalphabetic tools do not apply.

## Cryptanalysis

- Seed brute force: \(10^m\) (same as GAK).
- Cribs on first \(m\) positions recover numeric seed.
- Ciphertext-autokey cribs must align with **ciphertext** letters at extension positions, not plaintext.

## Python Implementation

`cipherops/ciphers/classical.py::gronsfeld_autokey(..., extension="ciphertext")`

## Dataset

`datasets/fingerprinted/xgak-31415/data.jsonl`

## See also

- [`gak.md`](gak.md) — plaintext-autokey Gronsfeld
- [`autokey.md`](autokey.md) — alphabetic autokey family (including ciphertext-autokey)
