#!/usr/bin/env python3
"""Import the unsolved Noita eye-message corpus from the Eyes repository."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

EYES_REPO = "https://github.com/Null-H3x/Eyes.git"
EYES_CORPUS_REL = "noita_eye_core/corpus.json"
EYES_RAW_BASE5_REL = "data/Raw Base5"

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "datasets" / "unsolved" / "noita-eye-messages"
MANIFEST_PATH = ROOT / "datasets" / "unsolved" / "manifest.json"
MATH_REF = "docs/math-formulas/noita-eye.md"
SLUG = "noita-eye-messages"

EXPECTED_LENGTHS = (99, 103, 118, 102, 137, 124, 119, 120, 114)
EXPECTED_LABELS = (
    "East 1",
    "West 1",
    "East 2",
    "West 2",
    "East 3",
    "West 3",
    "East 4",
    "West 4",
    "East 5",
)


def sha256_json(value: object) -> str:
    payload = json.dumps(value, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def slugify_label(label: str) -> str:
    return label.lower().replace(" ", "-")


def fetch_corpus(source: Path | None, clone: bool) -> dict:
    if source is not None:
        path = source / EYES_CORPUS_REL if source.is_dir() else source
        if not path.is_file():
            raise FileNotFoundError(f"Corpus not found: {path}")
        return json.loads(path.read_text(encoding="utf-8"))

    if clone:
        with tempfile.TemporaryDirectory(prefix="eyes-import-") as tmp:
            tmp_path = Path(tmp)
            subprocess.run(
                ["git", "clone", "--depth", "1", EYES_REPO, str(tmp_path)],
                check=True,
                capture_output=True,
                text=True,
            )
            path = tmp_path / EYES_CORPUS_REL
            raw = json.loads(path.read_text(encoding="utf-8"))
            maybe_copy_raw_base5(tmp_path)
            raw["_imported_from"] = EYES_REPO
            return raw

    bundled = OUT_DIR / "corpus.json"
    if bundled.is_file():
        return json.loads(bundled.read_text(encoding="utf-8"))

    raise FileNotFoundError(
        "No corpus source found. Pass --source PATH, use --clone, or keep "
        f"bundled {bundled}."
    )


def validate_corpus(raw: dict) -> None:
    deck_size = int(raw["deck_size"])
    labels = tuple(str(x) for x in raw["message_labels"])
    lengths = tuple(int(x) for x in raw["message_lengths"])
    cts = [tuple(int(x) for x in ct) for ct in raw["ciphertexts"]]

    if deck_size != 83:
        raise ValueError(f"expected deck_size 83, got {deck_size}")
    if len(cts) != 9:
        raise ValueError(f"expected 9 messages, got {len(cts)}")
    if labels != EXPECTED_LABELS:
        raise ValueError(f"unexpected labels: {labels}")
    if lengths != EXPECTED_LENGTHS:
        raise ValueError(f"unexpected lengths: {lengths}")

    for idx, ct in enumerate(cts):
        if len(ct) != lengths[idx]:
            raise ValueError(f"message {idx}: length mismatch")
        for symbol in ct:
            if not 0 <= symbol < deck_size:
                raise ValueError(f"message {idx}: symbol {symbol} out of range")

    # Universal header anomaly observed across all nine messages.
    if not all(ct[1] == 66 and ct[2] == 5 for ct in cts):
        raise ValueError("expected CT[1]=66 and CT[2]=5 across all messages")


def build_records(raw: dict) -> list[dict]:
    deck_size = int(raw["deck_size"])
    labels = [str(x) for x in raw["message_labels"]]
    lengths = [int(x) for x in raw["message_lengths"]]
    cts = [list(int(x) for x in ct) for ct in raw["ciphertexts"]]
    sigma0 = raw.get("sigma0_ct_targets")

    records: list[dict] = []
    for idx, (label, ct, length) in enumerate(zip(labels, cts, lengths)):
        record = {
            "id": f"{SLUG}-{slugify_label(label)}",
            "plaintext": None,
            "ciphertext": ct,
            "cipher_family": "noita-eye",
            "params": {
                "deck_size": deck_size,
                "label": label,
                "message_index": idx,
                "alphabet": "integer-mod-83",
                "hypothesis": "polyalphabetic_shared_keystream",
            },
            "math_ref": MATH_REF,
            "era": "unsolved",
            "validation": {
                "plaintext_sha256": None,
                "ciphertext_sha256": sha256_json(ct),
                "roundtrip_verified": False,
                "encrypt_only": False,
                "status": "unsolved",
                "symbol_range_ok": True,
                "length": length,
            },
            "difficulty": None,
            "source": {
                "repository": "https://github.com/Null-H3x/Eyes",
                "corpus_path": EYES_CORPUS_REL,
                "origin": raw.get("_source", "https://noita-eyes.neocities.org/"),
            },
            "metadata": {
                "header_anomaly": {"index_1": ct[1], "index_2": ct[2]},
            },
        }
        if sigma0 is not None and idx < len(sigma0):
            record["metadata"]["sigma0_ct_target"] = int(sigma0[idx])
        records.append(record)
    return records


def write_manifest(record_count: int) -> None:
    MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
    manifest = [
        {
            "slug": SLUG,
            "count": record_count,
            "path": str(OUT_DIR / "data.jsonl"),
            "status": "unsolved",
            "source_repo": "https://github.com/Null-H3x/Eyes",
            "math_ref": MATH_REF,
        }
    ]
    MANIFEST_PATH.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def maybe_copy_raw_base5(source_root: Path | None) -> None:
    if source_root is None:
        return
    src = source_root / EYES_RAW_BASE5_REL
    if src.is_file():
        shutil.copy2(src, OUT_DIR / "raw-base5.txt")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source",
        type=Path,
        help="Path to Eyes repo checkout or corpus.json file",
    )
    parser.add_argument(
        "--clone",
        action="store_true",
        help=f"Clone {EYES_REPO} temporarily to refresh corpus data",
    )
    args = parser.parse_args()

    raw = fetch_corpus(args.source, args.clone)
    validate_corpus(raw)
    records = build_records(raw)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "corpus.json").write_text(
        json.dumps(raw, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    data_path = OUT_DIR / "data.jsonl"
    with data_path.open("w", encoding="utf-8") as fh:
        for record in records:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")

    write_manifest(len(records))

    source_root = args.source if args.source and args.source.is_dir() else None
    if not args.clone:
        maybe_copy_raw_base5(source_root)

    print(f"wrote {data_path} ({len(records)} records)")
    print(f"wrote {OUT_DIR / 'corpus.json'}")
    print(f"wrote {MANIFEST_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
