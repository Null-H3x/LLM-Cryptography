# Random Test

Seeded random-plaintext corpus and comprehensive function tests for all **77** cipher variants in `cipherops/ciphers/registry.py`.

## Layout

```
random test/
  manifest.json          # generation metadata + per-slug paths
  corpus/
    <slug>/data.jsonl    # 3 random plaintext samples per cipher
  results/
    report.json          # machine-readable full results
    report.md            # human-readable break summary
    latest-run.txt       # timestamp of last suite run
```

## Regenerate corpus

```bash
PYTHONPATH=. python3 scripts/generate_random_test_corpus.py --seed 7689 --samples 3
```

## Run comprehensive tests

```bash
PYTHONPATH=. python3 scripts/run_random_test_suite.py
```

### Tests per record

| Test | Type | Description |
|------|------|-------------|
| `registry_lookup` | hard | `get_cipher(slug)` resolves |
| `encrypt` | hard | live encrypt does not crash |
| `corpus_ciphertext` | soft | stored vs live ciphertext match |
| `decrypt_roundtrip` | hard | decrypt matches plaintext (normalized) |
| `reencrypt_deterministic` | soft | re-encrypt equals first ciphertext |
| `profile` | hard | `analyze_ciphertext` returns full property bundle |
| `classifier` | hard | `classify_ciphertext(full=True)` returns hypotheses |
| `classifier_family_hit` | soft | expected family in top-3 hypotheses |
| `prepare_run` | hard | preflight steps 1–5 complete without exception |
| `pipeline_smoke` | hard | `run_findings_loop` for propagator-backed ciphers |

**Hard breaks** are exceptions or crypto I/O failures. **Soft fails** are heuristic misclassification or non-deterministic output — expected for some families.

## Latest run (seed 7689)

| Metric | Count |
|--------|------:|
| Records | 231 |
| Hard breaks | 0 |
| Soft fails | 127 |
| Clean records | 231 |

### Findings from initial run

1. **Four-square decrypt (fixed)** — `four_square()` re-applied plaintext digraph padding rules to ciphertext, breaking decrypt when the ciphertext contained duplicate letters (e.g. `BAAW…`). Fixed via `_ciphertext_pairs()` in `cipherops/ciphers/polygraphic.py`.
2. **Nihilist autokey (ciphertext extension)** — digit-space ciphertext cannot run through the alpha-only `stream_extension` propagator; pipeline smoke test skips these by design.
3. **Classifier soft fails (127)** — short random plaintext often yields flat statistics; top-3 family hits miss for ~55% of variants (modern AEAD, transposition, substitution, hashes). These are heuristic limits, not crashes.
