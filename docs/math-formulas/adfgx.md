# ADFGX Cipher

## Mathematical Definition

Two-stage WWI German cipher:

1. **Fractionation:** Map letters through keyed $5 \times 5$ Polybius square to ADFGX digraphs
2. **Transposition:** Columnar transposition with keyword

$$C = \Pi_K(\text{Frac}_{ADFGX}(\text{Polybius}_S(P)))$$

## Python Implementation

See `cipherops/ciphers/fractionated.py::adfgx`.

## Dataset

Validated examples: `datasets/fingerprinted/adfgx-keys/data.jsonl`
