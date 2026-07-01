# ADFGVX Cipher

## Mathematical Definition

Extension of ADFGX using a $6 \times 6$ Polybius square (A-Z + 0-9) and ADFGVX labels:

$$C = \Pi_K(\text{Frac}_{ADFGVX}(\text{Polybius}_S(P)))$$

## Python Implementation

See `cipherops/ciphers/fractionated.py::adfgvx`.

## Dataset

Validated examples: `datasets/fingerprinted/adfgvx-keys/data.jsonl`
