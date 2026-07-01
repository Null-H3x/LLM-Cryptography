# Polybius Square Cipher

## Mathematical Definition

Maps each letter to coordinate pair $(r,c)$ in a keyed $5 \times 5$ grid (I/J merged):

$$E(L) = (r(L)+1)(c(L)+1) \text{ as decimal digit pair}$$

## Python Implementation

See `cipherops/ciphers/classical.py::polybius_square`.

## Dataset

Validated examples: `datasets/fingerprinted/polybius-square/data.jsonl`
