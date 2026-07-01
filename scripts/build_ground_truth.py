#!/usr/bin/env python3
"""Build audited ground-truth corpus linking math docs, ciphers, and datasets."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from cipherops.ciphers.registry import CIPHER_REGISTRY

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "Pre-LLM-Ingestion" / "processed"
QNA_OVERRIDES = OUT_DIR / "cipher-qna-overrides.jsonl"

UNSOLVED_CORPORA = [
    {
        "cipher_family": "noita-eye",
        "variant_slug": "noita-eye-messages",
        "params": {
            "deck_size": 83,
            "num_messages": 9,
            "hypothesis": "polyalphabetic_shared_keystream",
        },
        "math_ref": "docs/math-formulas/noita-eye.md",
        "difficulty": None,
        "variants": ["noita-eye-messages"],
        "dataset_path": "datasets/unsolved/noita-eye-messages/data.jsonl",
        "properties_path": "datasets/ciphertext-properties/noita-eye-messages/properties.jsonl",
        "audit_status": "unsolved_corpus_imported",
        "status": "unsolved",
        "source_repo": "https://github.com/Null-H3x/Eyes",
    },
]


def _load_qna_overrides() -> dict[str, dict]:
    if not QNA_OVERRIDES.is_file():
        return {}
    overrides: dict[str, dict] = {}
    for line in QNA_OVERRIDES.read_text(encoding="utf-8").splitlines():
        if line.strip():
            row = json.loads(line)
            overrides[row["variant_slug"]] = row
    return overrides


def _default_qna(spec) -> dict:
    return {
        "instruction": f"Describe the {spec.family} cipher variant '{spec.slug}' and its core formula.",
        "input": "",
        "output": (
            f"The {spec.family} cipher ({spec.slug}) is defined in {spec.math_ref}. "
            f"Parameters: {json.dumps(spec.params)}. "
            f"Validated examples live in datasets/fingerprinted/{spec.slug}/data.jsonl."
        ),
        "math_ref": spec.math_ref,
        "cipher_family": spec.family,
        "variant_slug": spec.slug,
    }


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    overrides = _load_qna_overrides()

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
                "properties_path": f"datasets/ciphertext-properties/{spec.slug}/properties.jsonl",
                "audit_status": "math_implementation_verified",
                "status": "solved",
            }
        )

    for corpus in UNSOLVED_CORPORA:
        records.append(dict(corpus))

    ground_truth = OUT_DIR / "cipher-ground-truth.jsonl"
    with ground_truth.open("w", encoding="utf-8") as fh:
        for record in records:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")

    instruct_path = OUT_DIR / "cipher-qna-ground-truth.jsonl"
    with instruct_path.open("w", encoding="utf-8") as fh:
        for spec in CIPHER_REGISTRY:
            qna = overrides.get(spec.slug, _default_qna(spec))
            if "variant_slug" not in qna:
                qna = {**qna, "variant_slug": spec.slug}
            fh.write(json.dumps(qna, ensure_ascii=False) + "\n")

        for corpus in UNSOLVED_CORPORA:
            fh.write(
                json.dumps(
                    {
                        "instruction": (
                            "Describe the unsolved Noita eye-message corpus and the leading "
                            "cryptanalytic hypothesis."
                        ),
                        "input": "",
                        "output": (
                            f"The Noita eye messages ({corpus['variant_slug']}) are documented in "
                            f"{corpus['math_ref']}. Nine ciphertexts over a deck of size 83; plaintext "
                            f"is unknown. Leading model: polyalphabetic cipher with a shared "
                            f"position-indexed keystream (in depth). Records live in "
                            f"{corpus['dataset_path']}."
                        ),
                        "math_ref": corpus["math_ref"],
                        "cipher_family": corpus["cipher_family"],
                        "variant_slug": corpus["variant_slug"],
                        "status": "unsolved",
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )

    solved = sum(1 for r in records if r.get("status") == "solved")
    unsolved = sum(1 for r in records if r.get("status") == "unsolved")
    print(f"wrote {ground_truth} ({len(records)} records: {solved} solved, {unsolved} unsolved)")
    print(f"wrote {instruct_path} ({len(records)} records, {len(overrides)} Q&A overrides applied)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
