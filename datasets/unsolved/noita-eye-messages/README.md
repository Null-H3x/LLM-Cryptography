# Noita Eye Messages — Unsolved Corpus

Nine ciphertext messages from the Noita game eye puzzle. **No plaintext is known.**

| Field | Value |
|-------|-------|
| Source | [Null-H3x/Eyes](https://github.com/Null-H3x/Eyes) (`noita_eye_core/corpus.json`) |
| Origin | [noita-eyes.neocities.org](https://noita-eyes.neocities.org/) |
| Alphabet | Integers `0..82` (deck size 83) |
| Status | `unsolved` |

## Files

- `data.jsonl` — one record per message (`plaintext: null`)
- `corpus.json` — bundled canonical corpus (byte-synced with Eyes)
- `raw-base5.txt` — optional base-5 trigram export from Eyes `data/Raw Base5`

## Refresh from upstream

```bash
PYTHONPATH=. python3 scripts/import_eyes_corpus.py --clone
```

See `docs/math-formulas/noita-eye.md` for cryptanalytic context.
