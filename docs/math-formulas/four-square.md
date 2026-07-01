# Four-Square Cipher

## Mathematical Definition

Digraph substitution using four $5 \times 5$ matrices (TL keyed, TR standard, BL standard, BR keyed):

For plaintext digraph $(p_1, p_2)$:
$$c_1 = TR[r_{TL}(p_1)][c_{BR}(p_2)], \quad c_2 = BL[r_{BR}(p_2)][c_{TL}(p_1)]$$

## Python Implementation

See `cipherops/ciphers/polygraphic.py::four_square`.

## Dataset

Validated examples: `datasets/fingerprinted/four-square-keys/data.jsonl`
