# Simple Substitution Cipher

## Mathematical Definition

A permutation $\sigma$ on $\mathbb{Z}_{26}$:

$$E(x) = \sigma(x) \mod 26, \quad D(y) = \sigma^{-1}(y) \mod 26$$

## Python Implementation

See `cipherops/ciphers/classical.py::simple_substitution`.

## Dataset

Validated examples: `datasets/fingerprinted/substitution-qwerty/data.jsonl`
