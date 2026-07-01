# Fractionated Morse Cipher

## Mathematical Definition

Combines Morse code with Polybius fractionation:

1. Convert each letter to Morse (`.`→1, `-`→2)
2. Separate letters with delimiter `33`
3. Pair digits and map through keyed Polybius square

$$E(L_i) = \text{PairMap}(\text{MorseDigits}(L_i))$$

## Notes

This repository uses an encrypt-validated variant. Decryption is lossy through Polybius coordinate reduction; dataset entries are marked `encrypt_only`.

## Python Implementation

See `cipherops/ciphers/fractionated.py::fractionated_morse`.

## Dataset

Validated examples: `datasets/fingerprinted/fractionated-morse/data.jsonl`
