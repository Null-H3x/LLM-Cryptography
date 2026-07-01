# Math Formulas Documentation

This folder contains mathematical definitions and implementations for cryptographic ciphers.

## 📚 Files

| File | Description |
|------|-------------|
| `definitions.md` | Variable conventions (P, C, K, x, k) and universal notation reference |
| `caesar.md` | Caesar/ROT cipher: E_k(x) = (x + k) mod 26 |
| `affine.md` | Affine cipher: E_{a,b}(x) = (a*x + b) mod 26 |
| `vigenere.md` | Polyalphabetic cipher with repeating key |
| `playfair.md` | Digraph substitution using 5x5 matrix |
| `hill.md` | Matrix-based polygraphic cipher |

## 🔍 Variable Conventions

| Symbol | Meaning |
|--------|---------|
| **P** | Plaintext |
| **C** | Ciphertext |
| **K** | Key |
| **x**, **y** | Character indices (A=0, B=1, ..., Z=25) |
| **k** | Shift amount / key value |
| **a**, **b** | Affine cipher parameters |

## 💻 Python Implementations

Each formula file includes working Python code for encryption/decryption.
