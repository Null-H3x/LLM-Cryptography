# Homophonic Substitution Cipher

## Mathematical Definition

Each plaintext letter maps to one of several homophonic ciphertext symbols (commonly numeric) to flatten frequency distributions:

$$E(x) = h_x \in H(x), \quad D(c) = x \text{ where } c \in H(x)$$

## Python Implementation

See `cipherops/ciphers/classical.py::homophonic_substitution`.

## Dataset

Validated examples: `datasets/fingerprinted/homophonic-basic/data.jsonl`
