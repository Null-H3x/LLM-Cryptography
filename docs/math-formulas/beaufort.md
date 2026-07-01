# Beaufort Cipher

## Mathematical Definition

Reciprocal polyalphabetic cipher:

$$E_K(x_i) = D_K(x_i) = (k_{i \mod m} - x_i) \mod 26$$

## Python Implementation

See `cipherops/ciphers/classical.py::beaufort`.

## Dataset

Validated examples: `datasets/fingerprinted/beaufort-keyword/data.jsonl`
