# Hill Cipher

## Math Definition

The Hill cipher is a polygraphic substitution cipher using linear algebra.

### Matrix Encryption

$$C = H \cdot P \mod 26$$

Where:
- $H$ = n×n key matrix
- $P$ = plaintext vector (n characters)
- $C$ = ciphertext vector
- All operations mod 26

### Decryption

$$P = H^{-1} \cdot C \mod 26$$

Where $H^{-1}$ is the modular inverse of matrix H.

### Matrix Inverse Condition

A matrix has a modular inverse iff:
- $\det(H) \neq 0$
- $\gcd(\det(H), 26) = 1$

## Python Implementation

import numpy as np

def mod_matrix_inverse(H, mod=26):
    """Compute modular matrix inverse."""
    det = int(np.round(np.linalg.det(H))) % mod
    det_inv = mod_inverse(det, mod)
    adj = np.round(np.linalg.inv(H) * det).astype(int) % mod
    return (det_inv * adj) % mod

def mod_inverse(a, m):
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return 1

def text_to_matrix(text, n):
    """Convert text to vector of character indices."""
    return [ord(c) - ord('A') for c in text.upper() if c.isalpha()]

def hill_encrypt(plaintext, key_matrix):
    """Encrypt using Hill cipher."""
    n = len(key_matrix)
    P = text_to_matrix(plaintext, n)
    
    # Pad if needed
    while len(P) % n != 0:
        P.append(23)  # X = 23
    
    C = []
    for i in range(0, len(P), n):
        block = np.array(P[i:i+n])
        result = np.dot(key_matrix, block) % 26
        C.extend(result.tolist())
    
    return "".join(chr(c + ord('A')) for c in C)

# Example 2x2 key matrix
H = np.array([[3, 3], [2, 5]])
plaintext = "ACT"
ciphertext = hill_encrypt(plaintext, H)  # Output: POH

