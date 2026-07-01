#!/usr/bin/env python3
"""Validate fingerprinted datasets against cipher implementations."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from cipherops.ciphers.registry import get_cipher

# Reuse normalization rules from generator
from scripts.generate_datasets import _roundtrip_ok  # noqa: E402


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
        if record.get("validation", {}).get("encrypt_only"):
            continue
        plaintext = record["plaintext"]
        ciphertext = record["ciphertext"]
        decrypted = spec.decrypt(ciphertext)
        if not _roundtrip_ok(plaintext, decrypted, spec.family):
            errors.append(f"{path}:{line_no} roundtrip mismatch for {record['id']}")
    return errors


def main() -> None:
    root = Path("datasets/fingerprinted")
    all_errors: list[str] = []
    for data_file in sorted(root.glob("*/data.jsonl")):
        all_errors.extend(validate_file(data_file))

    if all_errors:
        print("\n".join(all_errors))
        sys.exit(1)
    print(f"validated {len(list(root.glob('*/data.jsonl')))} dataset files")


if __name__ == "__main__":
    main()
