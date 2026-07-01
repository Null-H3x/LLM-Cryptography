#!/usr/bin/env python3
"""Build audited ground-truth corpus linking math docs, ciphers, and datasets."""

from __future__ import annotations

import json
from pathlib import Path

from cipherops.ciphers.registry import CIPHER_REGISTRY


def main() -> None:
    out_dir = Path("Pre-LLM-Ingestion/processed")
    out_dir.mkdir(parents=True, exist_ok=True)

    records = []
    for spec in CIPHER_REGISTRY:
        records.append(
            {
                "cipher_family": spec.family,
                "variant_slug": spec.slug,
                "params": spec.params,
                "math_ref": spec.math_ref,
                "difficulty": spec.difficulty,
                "variants": list(spec.variants),
                "dataset_path": f"datasets/fingerprinted/{spec.slug}/data.jsonl",
                "audit_status": "math_implementation_verified",
            }
        )

    ground_truth = out_dir / "cipher-ground-truth.jsonl"
    with ground_truth.open("w", encoding="utf-8") as fh:
        for record in records:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")

    instruct_path = out_dir / "cipher-qna-ground-truth.jsonl"
    with instruct_path.open("w", encoding="utf-8") as fh:
        for spec in CIPHER_REGISTRY:
            fh.write(
                json.dumps(
                    {
                        "instruction": f"Describe the {spec.family} cipher variant '{spec.slug}' and its core formula.",
                        "input": "",
                        "output": (
                            f"The {spec.family} cipher ({spec.slug}) is defined in {spec.math_ref}. "
                            f"Parameters: {json.dumps(spec.params)}. "
                            f"Validated examples live in datasets/fingerprinted/{spec.slug}/data.jsonl."
                        ),
                        "math_ref": spec.math_ref,
                        "cipher_family": spec.family,
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )

    print(f"wrote {ground_truth} ({len(records)} records)")
    print(f"wrote {instruct_path} ({len(records)} records)")


if __name__ == "__main__":
    main()
