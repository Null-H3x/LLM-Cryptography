# Repository rename → `h3x-cipherops`

The codebase is rebranded to **H3X CipherOps**. GitHub still uses the old repo name until an owner renames it.

## One-time (GitHub admin)

1. Open **Settings → General → Repository name**
2. Change `LLM-Cryptography` → `h3x-cipherops`
3. Locally:

```bash
git remote set-url origin https://github.com/Null-H3x/h3x-cipherops.git
git fetch origin
```

GitHub redirects the old URL for a while; update remotes and clone URLs when convenient.

## Already on `main`

`main` includes: autostream ciphers (77 variants), constraint propagators, findings pipeline, HTML solver dash, stop diagnosis, crib auto-fill, and README reframe.

```bash
git checkout main
git pull origin main
PYTHONPATH=. python3 scripts/serve_constraints_dash.py
```
