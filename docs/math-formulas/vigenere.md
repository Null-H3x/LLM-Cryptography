# Vigenere Cipher

## Math Definition

Encryption: E_K(x_i) = (x_i + k_{i mod m}) mod 26
Decryption: D_K(y_i) = (y_i - k_{i mod m}) mod 26

Where:
- x_i = plaintext char index at position i
- K = key vector of length m
- k_j = key character index

## Python Implementation

def vigenere_encrypt(text, key):
    key = key.upper()
    result = ""
    for i, char in enumerate(text):
        if char.isalpha():
            k = ord(key[i % len(key)]) - ord('A')
            base = ord('A') if char.isupper() else ord('a')
            y = (ord(char) - base + k) % 26
            result += chr(y + base)
        else:
            result += char
    return result

def vigenere_decrypt(text, key):
    key = key.upper()
    result = ""
    for i, char in enumerate(text):
        if char.isalpha():
            k = ord(key[i % len(key)]) - ord('A')
            base = ord('A') if char.isupper() else ord('a')
            x = (ord(char) - base - k) % 26
            result += chr(x + base)
        else:
            result += char
    return result

# Example: vigenere_encrypt("HELLO", "KEY") -> "RIJVS"
