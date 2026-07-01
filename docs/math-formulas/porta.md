# Porta Cipher

## Mathematical Definition

Reciprocal polyalphabetic cipher using 13 paired alphabets keyed by letters A-M (N-Z wrap):

For key index $k \in \{0,\ldots,12\}$:
$$E(x) = \begin{cases} (x + k) \mod 13 + 13 & x < 13 \\ (x - 13 - k) \mod 13 & x \geq 13 \end{cases}$$

## Python Implementation

See `cipherops/ciphers/classical.py::porta`.

## Dataset

Validated examples: `datasets/fingerprinted/porta-keyword/data.jsonl`
