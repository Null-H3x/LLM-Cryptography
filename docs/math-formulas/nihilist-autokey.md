# Nihilist Autokey

Nihilist (Polybius + numeric key) with non-repeating digit stream extended from plaintext or ciphertext coordinates.

## Variants

| Slug | Extension |
|------|-----------|
| `nihilist-autokey-31415` | Plaintext Polybius digits mod 10 |
| `nihilist-autokey-ct-31415` | Prior ciphertext digit pairs |

After numeric seed `31415`, each letter consumes two stream digits for coordinate addition mod 10.

## Implementation

`cipherops/ciphers/classical.py::nihilist_autokey`, `nihilist_autokey_decrypt`

## Cryptanalysis

Non-periodic numeric seed space \(10^m\); same regime model as [`gronsfeld-autokey.md`](gronsfeld-autokey.md).

## Datasets

- `datasets/fingerprinted/nihilist-autokey-31415/data.jsonl`
- `datasets/fingerprinted/nihilist-autokey-ct-31415/data.jsonl`
