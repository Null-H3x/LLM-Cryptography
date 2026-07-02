#!/usr/bin/env python3
"""Generate random plaintext corpus for every registry cipher under ``random test/``."""

from __future__ import annotations

import argparse
import json
import sys
import traceback
from pathlib import Path

from cipherops.ciphers.registry import CIPHER_REGISTRY
from cipherops.ciphers.utils import sha256_text
from scripts.random_test_lib import (
    DEFAULT_SEED,
    RANDOM_TEST_ROOT_NAME,
    SAMPLES_PER_CIPHER,
    build_record,
    generate_plaintext,
    serialize_ciphertext,
)

ROOT = Path(__file__).resolve().parents[1]


def generate_corpus(
    *,
    seed: int = DEFAULT_SEED,
    samples: int = SAMPLES_PER_CIPHER,
    output_root: Path | None = None,
) -> dict:
    import random

    rng = random.Random(seed)
    out_root = output_root or (ROOT / RANDOM_TEST_ROOT_NAME)
    corpus_root = out_root / "corpus"
    corpus_root.mkdir(parents=True, exist_ok=True)

    manifest: list[dict] = []
    generation_errors: list[dict] = []

    for spec in CIPHER_REGISTRY:
        slug_dir = corpus_root / spec.slug
        slug_dir.mkdir(parents=True, exist_ok=True)
        records: list[dict] = []

        for sample_index in range(1, samples + 1):
            plaintext = generate_plaintext(spec, rng, sample_index)
            record = build_record(spec, plaintext, sample_index, seed=seed)
            prefix = f"{spec.slug}:sample{sample_index}"

            try:
                ciphertext = spec.encrypt(plaintext)
            except Exception as exc:
                generation_errors.append(
                    {
                        "slug": spec.slug,
                        "sample_index": sample_index,
                        "stage": "encrypt",
                        "error": f"{type(exc).__name__}: {exc}",
                        "traceback": traceback.format_exc(),
                        "plaintext_preview": plaintext[:120],
                    }
                )
                record["ciphertext"] = None
                record["generation"]["encrypt_error"] = str(exc)
                records.append(record)
                continue

            if not ciphertext and ciphertext != 0:
                generation_errors.append(
                    {
                        "slug": spec.slug,
                        "sample_index": sample_index,
                        "stage": "encrypt",
                        "error": "empty ciphertext",
                        "plaintext_preview": plaintext[:120],
                    }
                )
                record["ciphertext"] = ciphertext
                record["generation"]["encrypt_error"] = "empty ciphertext"
                records.append(record)
                continue

            record["ciphertext"] = serialize_ciphertext(ciphertext)
            record["ciphertext_sha256"] = sha256_text(
                json.dumps(ciphertext, ensure_ascii=True)
                if isinstance(ciphertext, list)
                else str(ciphertext)
            )

            if not spec.encrypt_only:
                try:
                    decrypted = spec.decrypt(ciphertext)
                    record["generation"]["decrypt_preview"] = str(decrypted)[:120]
                except Exception as exc:
                    generation_errors.append(
                        {
                            "slug": spec.slug,
                            "sample_index": sample_index,
                            "stage": "decrypt_at_generation",
                            "error": f"{type(exc).__name__}: {exc}",
                            "traceback": traceback.format_exc(),
                        }
                    )
                    record["generation"]["decrypt_error"] = str(exc)

            records.append(record)

        data_path = slug_dir / "data.jsonl"
        with data_path.open("w", encoding="utf-8") as fh:
            for record in records:
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")

        manifest.append(
            {
                "slug": spec.slug,
                "family": spec.family,
                "count": len(records),
                "path": str(data_path.relative_to(ROOT)),
                "encrypt_only": spec.encrypt_only,
            }
        )

    summary = {
        "seed": seed,
        "samples_per_cipher": samples,
        "cipher_count": len(CIPHER_REGISTRY),
        "record_count": len(CIPHER_REGISTRY) * samples,
        "generation_errors": generation_errors,
        "manifest": manifest,
    }

    (out_root / "manifest.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--samples", type=int, default=SAMPLES_PER_CIPHER)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / RANDOM_TEST_ROOT_NAME,
        help="Output directory (default: random test/)",
    )
    args = parser.parse_args()

    summary = generate_corpus(seed=args.seed, samples=args.samples, output_root=args.output)
    errors = summary["generation_errors"]
    print(f"Generated {summary['record_count']} records for {summary['cipher_count']} ciphers")
    print(f"Output: {args.output}")
    if errors:
        print(f"Generation errors: {len(errors)}", file=sys.stderr)
        for item in errors[:20]:
            print(f"  - {item['slug']} sample {item['sample_index']}: {item['error']}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
