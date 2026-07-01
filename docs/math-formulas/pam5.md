# PAM-5 (Pulse Amplitude Modulation, 5 Levels)

## Mathematical Definition

**PAM-5** maps digital symbols to one of **five amplitude levels** \(\mathcal{L} = \{0,1,2,3,4\}\) (often represented as voltages \(-2,-1,0,+1,+2\) on the wire).

Information capacity per symbol:

\[
H_5 = \log_2 5 \approx 2.3219 \text{ bits/symbol}
\]

### Dibit mode (implemented in this repo)

Used in teaching models of **1000BASE-T (4D-PAM5)**: each **dibit** (2 bits) maps to one of **four data levels**; level **4** is reserved for control / line coding (DC balance).

| Dibit | PAM level |
|-------|-----------|
| 00 | 0 |
| 01 | 1 |
| 10 | 2 |
| 11 | 3 |

**Encode:** 4-byte big-endian length + UTF-8 plaintext → bitstring → pad one zero bit if odd → dibit symbols 0–3.

**Decode:** symbol sequence → dibits → bytes → UTF-8 text.

### 4D-PAM5 (reference — not fully implemented)

Gigabit Ethernet encodes **8 bits** as **4 consecutive PAM-5 symbols** (4 dimensions × 5 levels). Requires trellis / Viterbi decoding on the physical layer — see [`encodings-catalog.md`](encodings-catalog.md).

---

## Cryptanalysis / detection

| Property | PAM-5 dibit ciphertext |
|----------|------------------------|
| Alphabet | Digits 0–3 (data mode) |
| Shannon entropy | ≤ 2 bits/symbol |
| Key space | 1 (encoding, not encryption) |
| Attack | Direct decode; no key |

---

## Python Implementation

See `cipherops/ciphers/encoding.py::pam5_encode`, `pam5_decode`.

## Dataset

Validated examples: `datasets/fingerprinted/pam5-dibit/data.jsonl`

## References

- IEEE 802.3 Clause 40 (1000BASE-T 4-PAM5)
- [`encodings-catalog.md`](encodings-catalog.md) — NRZ, Manchester, 8b/10b, etc.
