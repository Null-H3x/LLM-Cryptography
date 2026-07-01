# VIC Cipher (teaching model)

Soviet-era compound cipher — simplified teaching pipeline:

1. **Straddle checkerboard** → numeric string  
2. **Chain addition** mod 10 (non-carrying) with numeric key  
3. **Columnar transposition**

## Variant

| Slug | Chain key | Transposition key |
|------|-----------|-------------------|
| `vic-standard-31415` | `31415` | `PRIVATE` |

## Implementation

`cipherops/ciphers/vic.py::vic_encrypt`, `vic_decrypt`

## Dataset

`datasets/fingerprinted/vic-standard-31415/data.jsonl`

## Notes

Full historical VIC adds personal/date keys and disrupted transposition; this repo uses a fixed-parameter teaching instance.
