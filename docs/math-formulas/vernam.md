# Vernam One-Time Pad (manual)

Mod-26 addition with a non-repeating key as long as the message. Key must never be reused.

\[
E(p_i) = (p_i + k_i) \mod 26, \quad |K| \geq |P|
\]

## Variant

| Slug | Key |
|------|-----|
| `vernam-otp-demo` | Doubled book excerpt (demo OTP) |

## Cryptanalysis

Non-periodic, OTP-like. Key reuse → depth attack. See [`running-key.md`](running-key.md) for related book attacks.

## Implementation

`cipherops/ciphers/classical.py::vernam`, `vernam_decrypt`

## Dataset

`datasets/fingerprinted/vernam-otp-demo/data.jsonl`
