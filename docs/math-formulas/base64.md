# Base64 Encoding

## Mathematical Definition

Maps binary data to ASCII using 64-character alphabet with padding:

$$\text{Base64}(b_{1:3}) = \text{Index}^{-1}\left(\frac{b_1 \cdot 2^{16} + b_2 \cdot 2^8 + b_3}{64^k}\right)$$

## Python Implementation

See `cipherops/ciphers/encoding.py::base64_encode`.

## Dataset

Validated examples: `datasets/fingerprinted/b64/data.jsonl`
