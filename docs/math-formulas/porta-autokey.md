# Porta Autokey

Porta combiner with alphabetic priming key and plaintext/ciphertext keystream extension. Non-periodic — same analysis regime as [`autokey.md`](autokey.md).

## Variants

| Slug | Extension |
|------|-----------|
| `porta-autokey-standard` | Plaintext |
| `porta-autokey-ciphertext` | Ciphertext |

\[
E(p_i) = \text{Porta}(p_i, k_i), \quad k_i = K_i \text{ or extended stream}
\]

## Implementation

`cipherops/ciphers/classical.py::porta_autokey`, `porta_autokey_decrypt`

## Datasets

- `datasets/fingerprinted/porta-autokey-standard/data.jsonl`
- `datasets/fingerprinted/porta-autokey-ciphertext/data.jsonl`
