# Rail Fence Cipher

## Mathematical Definition

Transposition over $n$ rails using zigzag write order $\pi$:

$$\text{Write row } r_i = i \mod (2(n-1)) \text{ (bounce pattern)}, \quad C = \text{read rows sequentially}$$

## Python Implementation

See `cipherops/ciphers/transposition.py::rail_fence`.

## Parameters

| Param | Meaning |
|-------|---------|
| `rails` | Number of fence rows (typically 2-10) |

## Dataset

Validated examples: `datasets/fingerprinted/railfence-3/data.jsonl`
