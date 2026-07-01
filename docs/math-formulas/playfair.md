# Playfair Cipher

## Math Definition

The Playfair cipher encrypts pairs of letters (digraphs) using a 5x5 matrix.

### Matrix Construction

1. Fill 5x5 matrix with key (removing duplicates), then remaining alphabet
2. I/J are combined in one cell
3. If both letters same, insert X between them

### Encryption Rules

For digraph PL = (P1, P2) with coordinates:
- P1: (r1, c1)
- P2: (r2, c2)

1. **Same row**: Shift right
   - C1 = (r1, (c1+1) mod 5)
   - C2 = (r1, (c2+1) mod 5)

2. **Same column**: Shift down
   - C1 = ((r1+1) mod 5, c1)
   - C2 = ((r2+1) mod 5, c2)

3. **Rectangle**: Swap columns
   - C1 = (r1, c2)
   - C2 = (r2, c1)

### Decryption Rules

Reverse of encryption rules.

## Python Implementation

def find_position(matrix, char):
    for r in range(5):
        for c in range(5):
            if matrix[r][c] == char:
                return (r, c)
    return None

def playfair_encrypt(text, key):
    # Build matrix
    key = key.upper().replace("J", "I")
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    matrix_chars = ""
    for ch in key + alphabet:
        if ch not in matrix_chars:
            matrix_chars += ch
    
    matrix = [list(matrix_chars[i*5:(i+1)*5]) for i in range(5)]
    
    # Prepare plaintext pairs
    text = text.upper().replace("J", "I")
    pairs = []
    i = 0
    while i < len(text):
        if i + 1 >= len(text):
            pairs.append((text[i], 'X'))
            i += 1
        elif text[i] == text[i+1]:
            pairs.append((text[i], 'X'))
            i += 1
        else:
            pairs.append((text[i], text[i+1]))
            i += 2
    
    # Encrypt
    result = ""
    for p1, p2 in pairs:
        r1, c1 = find_position(matrix, p1)
        r2, c2 = find_position(matrix, p2)
        
        if r1 == r2:  # Same row
            c1 = (c1 + 1) % 5
            c2 = (c2 + 1) % 5
            result += matrix[r1][c1] + matrix[r2][c2]
        elif c1 == c2:  # Same column
            r1 = (r1 + 1) % 5
            r2 = (r2 + 1) % 5
            result += matrix[r1][c1] + matrix[r2][c2]
        else:  # Rectangle
            result += matrix[r1][c2] + matrix[r2][c1]
    
    return result

# Example: playfair_encrypt("HELLO", "KEY") -> (depends on matrix)
