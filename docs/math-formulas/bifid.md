# Bifid Cipher

## Mathematical Definition

Fractionating cipher over Polybius coordinates:

1. Map each letter to $(r,c)$
2. Concatenate row digits then column digits
3. Re-pair and map back to letters

$$S = r_1 r_2 \ldots r_n c_1 c_2 \ldots c_n, \quad C_i = \text{Square}(S_{2i}, S_{2i+1})$$

## Python Implementation

See `cipherops/ciphers/fractionated.py::bifid`.

## Dataset

Validated examples: `datasets/fingerprinted/bifid-keyword/data.jsonl`
