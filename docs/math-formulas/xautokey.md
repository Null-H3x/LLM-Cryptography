# X-Autokey (additive)

Vigenère-style autokey where post-seed keystream indices derive from **both** lagged plaintext and ciphertext (classical analogue of Eyes XGAK indexing).

## Variants

| Slug | Mode | Keystream after seed |
|------|------|----------------------|
| `xautokey-sum-key` | sum | \(k_i = (p_{i-|K|} + c_{i-|K|}) \mod 26\) |
| `xautokey-diff-key` | diff | \(k_i = (c_{i-|K|} - p_{i-|K|}) \mod 26\) |

\[
E(p_i) = (p_i + k_i) \mod 26
\]

Non-periodic. See [`autokey.md`](autokey.md) for cryptanalysis workflow.

## Implementation

`cipherops/ciphers/classical.py::xautokey`, `xautokey_decrypt`

## Datasets

- `datasets/fingerprinted/xautokey-sum-key/data.jsonl`
- `datasets/fingerprinted/xautokey-diff-key/data.jsonl`
