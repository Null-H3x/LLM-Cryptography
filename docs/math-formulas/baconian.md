# Baconian Cipher

## Mathematical Definition

Maps each plaintext letter to a 5-bit binary codeword (A=00000 ... Z=10101 in standard Bacon biliteral alphabet), rendered as `{A,B}` steganographic symbols.

$$E(L) = \text{Bacon5}(L) \rightarrow \{A,B\}^5$$

## Python Implementation

See `cipherops/ciphers/classical.py::baconian_encode`.

## Dataset

Validated examples: `datasets/fingerprinted/baconian-ab/data.jsonl`
