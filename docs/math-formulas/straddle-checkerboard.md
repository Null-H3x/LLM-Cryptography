# Straddle Checkerboard Cipher

## Mathematical Definition

Numeric substitution using a checkerboard layout: high-frequency letters map to fixed two-digit codes `{row}{col}`.

Default layout (fixed-width variant in this repo):

| Row | Letters |
|-----|---------|
| 0 | ETAOINSHRD |
| 1 | LCFMPUGWYB |
| 2 | VKJQZX |

$$E(L) = \text{row}(L)\,\text{col}(L)$$

## Python Implementation

See `cipherops/ciphers/fractionated.py::straddle_checkerboard`.

## Dataset

Validated examples: `datasets/fingerprinted/straddle-default/data.jsonl`
