# Math Formulas Documentation

Mathematical definitions, variables, and validated Python implementations for classical ciphers used in LLM pre-training.

## Core Reference

| File | Description |
|------|-------------|
| `definitions.md` | Universal notation (P, C, K, x, k) |
| `cipher-families.md` | Cipher taxonomy and quick reference |

## Cipher Formula Files

| Cipher | File | Dataset Slug |
|--------|------|--------------|
| Atbash | `atbash.md` | `atbash` |
| Caesar / ROT13 | `caesar.md` | `caesar-rot3`, `caesar-rot13` |
| Affine | `affine.md` | `affine-a2b5` |
| Rail Fence | `railfence.md` | `railfence-3` |
| Baconian | `baconian.md` | `baconian-ab` |
| Polybius Square | `polybius.md` | `polybius-square` |
| Simple Substitution | `substitution.md` | `substitution-qwerty` |
| Nomenclator | `nomenclator.md` | `nomenclator-basic` |
| Columnar Transposition | `columnar.md` | `columnar-keyword` |
| Autokey | `autokey.md` | `autokey-standard`, `autokey-beaufort` |
| Beaufort | `beaufort.md` | `beaufort-keyword` |
| Porta | `porta.md` | `porta-keyword` |
| Running Key | `running-key.md` | `running-key-book` |
| Vigenère | `vigenere.md` | `vigenere-keyword` |
| Gronsfeld | `gronsfeld.md` | `gronsfeld-31415` |
| Homophonic | `homophonic.md` | `homophonic-basic` |
| Four-Square | `four-square.md` | `four-square-keys` |
| Hill | `hill.md` | `hill-2x2` |
| Playfair | `playfair.md` | `playfair-keyword` |
| ADFGVX | `adfgvx.md` | `adfgvx-keys` |
| ADFGX | `adfgx.md` | `adfgx-keys` |
| Bifid | `bifid.md` | `bifid-keyword` |
| Straddle Checkerboard | `straddle-checkerboard.md` | `straddle-default` |
| Trifid | `trifid.md` | `trifid-keyword` |
| Base64 | `base64.md` | `b64` |
| Fractionated Morse | `fractionated-morse.md` | `fractionated-morse` |

## Implementation Source

All formulas map to validated code in `cipherops/ciphers/` and reproducible datasets under `datasets/fingerprinted/`.

Regenerate datasets:

```bash
PYTHONPATH=. python3 scripts/generate_datasets.py
PYTHONPATH=. python3 scripts/validate_datasets.py
```
