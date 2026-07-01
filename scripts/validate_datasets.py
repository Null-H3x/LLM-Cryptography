#!/usr/bin/env python3
"""Validate fingerprinted datasets against cipher implementations."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from cipherops.ciphers.registry import CIPHER_REGISTRY, get_cipher

# Reuse normalization rules from generator
from scripts.generate_datasets import _roundtrip_ok  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
NON_DETERMINISTIC = frozenset({"fernet", "rsa-oaep-hybrid"})


def validate_file(path: Path) -> list[str]:
    errors: list[str] = []
    slug = path.parent.name
    try:
        spec = get_cipher(slug)
    except KeyError:
        return [f"{path}: unknown cipher slug {slug}"]

    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        record = json.loads(line)
        prefix = f"{path}:{line_no}"
        plaintext = record["plaintext"]
        ciphertext = record["ciphertext"]

        if record.get("validation", {}).get("encrypt_only"):
            recomputed = spec.encrypt(plaintext)
            if recomputed != ciphertext:
                errors.append(f"{prefix}: encrypt_only ciphertext mismatch for {record['id']}")
            continue

        decrypted = spec.decrypt(ciphertext)
        if not _roundtrip_ok(plaintext, decrypted, spec.family):
            errors.append(f"{prefix}: roundtrip mismatch for {record['id']}")

        if slug not in NON_DETERMINISTIC:
            reencrypted = spec.encrypt(plaintext)
            if reencrypted != ciphertext:
                errors.append(f"{prefix}: re-encrypt mismatch for {record['id']}")

    return errors


def main() -> int:
    root = ROOT / "datasets" / "fingerprinted"
    data_files = sorted(root.glob("*/data.jsonl"))
    expected = len(CIPHER_REGISTRY)

    if not data_files:
        print(f"ERROR: no dataset files under {root} (wrong cwd?)", file=sys.stderr)
        return 1
    if len(data_files) != expected:
        print(
            f"ERROR: found {len(data_files)} dataset files, expected {expected} from registry",
            file=sys.stderr,
        )
        return 1

    all_errors: list[str] = []
    for data_file in data_files:
        all_errors.extend(validate_file(data_file))

    if all_errors:
        print("\n".join(all_errors))
        return 1
    print(f"validated {len(data_files)} dataset files ({expected} expected)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
