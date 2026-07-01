# Caesar Cipher

## 📐 Mathematical Definition

The Caesar cipher is a substitution cipher where each letter is shifted by a fixed number of positions in the alphabet.

### Encryption Function

$$E_k(x) = (x + k) \mod 26$$

Where:
- $x$ = plaintext character mapped to integer (A=0, B=1, ..., Z=25)
- $k$ = shift key (encryption key)
- $E_k(x)$ = ciphertext character as integer

### Decryption Function

$$D_k(y) = (y - k) \mod 26$$

Where:
- $y$ = ciphertext character mapped to integer
- $D_k(y)$ = plaintext character as integer

## 💻 Python Implementation

```python
def caesar_encrypt(text, shift):
    """Encrypt text using Caesar cipher with given shift."""
    result = ""
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            result += char
    return result

def caesar_decrypt(text, shift):
    """Decrypt Caesar cipher with given shift."""
    return caesar_encrypt(text, -shift)

# Example usage
plaintext = "HELLO WORLD"
ciphertext = caesar_encrypt(plaintext, 3)  # ROT3
print(ciphertext)  # KHOOR ZRUOG

decrypted = caesar_decrypt(ciphertext, 3)
print(decrypted)   # HELLO WORLD
```

## 🔍 Cryptanalysis Notes

- **Key space**: Only 25 possible keys (shift 0 is trivial)
- **Attack method**: Brute force (try all 25 shifts) or frequency analysis
- **Fingerprinting clues**:
  - Index of Coincidence remains ~0.068 for English (same as plaintext)
  - Letter distribution pattern preserved, just shifted

## 📊 Example Encryption Table (ROT3)

| Plaintext | H | E | L | L | O |   | W | O | R | L | D |
|-----------|---|---|---|---|---|---|---|---|---|---|---|
| Integer x | 7 | 4 | 11| 11| 14| - | 22| 14| 17| 11| 3 |
| Shift +3  |10 | 7 | 14| 14| 17| - | 25| 17| 20| 14| 6 |
| Ciphertext| K | H | O | O | R |   | Z | R | U | O | G |
