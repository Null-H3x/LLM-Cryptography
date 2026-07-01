# Atbash Cipher

## Mathematical Definition

Self-reciprocal monoalphabetic substitution over $\mathbb{Z}_{26}$:

$$E(x) = D(x) = (25 - x) \mod 26$$

Where $x$ is the plaintext character index (A=0, ..., Z=25).

## Python Implementation

```python
def atbash(text: str) -> str:
    return "".join(chr((25 - (ord(c.upper()) - 65)) % 26 + 65) for c in text if c.isalpha())
```

## Cryptanalysis Notes

- Key space: 1 (no key)
- Index of coincidence unchanged from English (~0.067)
- Reversed alphabet mapping

## Dataset

Validated examples: `datasets/fingerprinted/atbash/data.jsonl`
