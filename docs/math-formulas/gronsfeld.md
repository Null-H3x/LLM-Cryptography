# Gronsfeld Cipher

## Mathematical Definition

Vigenère variant where key digits map directly to shifts:

$$E_{i}(x) = (x + d_i) \mod 26, \quad d_i \in \{0,\ldots,9\}$$

## Python Implementation

See `cipherops/ciphers/classical.py::gronsfeld`.

## Dataset

Validated examples: `datasets/fingerprinted/gronsfeld-31415/data.jsonl`
