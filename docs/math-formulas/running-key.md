# Running Key Cipher

## Mathematical Definition

Vigenère-style encryption with a non-repeating keystream from a long reference text (book/page):

$$E_{i}(p_i) = (p_i + k_i) \mod 26, \quad k_i = \text{BookKey}_i, \quad |K| \geq |P|$$

## Python Implementation

See `cipherops/ciphers/classical.py::running_key`.

## Dataset

Validated examples: `datasets/fingerprinted/running-key-book/data.jsonl`
