# Enigma M3 (3-rotor teaching model)

Historical rotor machine with reflector B, compatible with standard Wehrmacht wirings (pycipher reference).

## Variant

| Slug | Rotors | Settings | Reflector |
|------|--------|----------|-----------|
| `enigma-iii-aaa-b` | I, II, III | AAA | B |

Self-reciprocal: encrypt and decrypt use the same machine settings.

## Implementation

`cipherops/ciphers/enigma.py::enigma`, `enigma_decrypt`

## Dataset

`datasets/fingerprinted/enigma-iii-aaa-b/data.jsonl`

## Cryptanalysis

Machine cipher — not periodic Vigenère. Commercial/historical attacks: cribs, plugboard constraint search, Bombe simulation (not automated in this repo).
