# Autokey Cipher

## Mathematical Definition

Polyalphabetic cipher where keystream extends with plaintext (standard) or uses Beaufort subtraction (beaufort variant):

**Standard:** $k_i = K_i$ for $i < |K|$, else $k_i = p_{i-|K|}$
$$E(p_i) = (p_i + k_i) \mod 26$$

**Beaufort variant:**
$$E(p_i) = (k_i - p_i) \mod 26$$

## Variants in Dataset

| Slug | Variant |
|------|---------|
| `autokey-standard` | Plaintext-extended Vigenère-style addition |
| `autokey-beaufort` | Plaintext-extended Beaufort subtraction |

## Python Implementation

See `cipherops/ciphers/classical.py::autokey`.

## Dataset

- `datasets/fingerprinted/autokey-standard/data.jsonl`
- `datasets/fingerprinted/autokey-beaufort/data.jsonl`
