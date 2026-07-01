# Columnar Transposition Cipher

## Mathematical Definition

Write plaintext in rows of $m = |K|$ columns, read columns in order sorted by key letters:

$$C = \text{ReadCols}(\text{WriteRows}(P, m), \text{sort}(K))$$

## Python Implementation

See `cipherops/ciphers/transposition.py::columnar_transposition`.

## Dataset

Validated examples: `datasets/fingerprinted/columnar-keyword/data.jsonl`
