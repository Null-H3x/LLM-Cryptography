# Book Cipher (coordinates)

Maps each plaintext letter to a **word.character** coordinate (1-indexed) into a fixed corpus excerpt — distinct from running-key (continuous excerpt keystream).

## Variant

| Slug | Format |
|------|--------|
| `book-cipher-coords` | `word.char` tokens (space-separated) |

## Implementation

`cipherops/ciphers/classical.py::book_cipher`, `book_cipher_decrypt`

Corpus: `RUNNING_KEY_TEXT` word list in `cipherops/ciphers/registry.py`.

## Dataset

`datasets/fingerprinted/book-cipher-coords/data.jsonl`
