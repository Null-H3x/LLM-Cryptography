#!/usr/bin/env python3
"""Comprehensive validation of math refs, registry, datasets, and cipher I/O."""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

from cipherops.ciphers.registry import CIPHER_REGISTRY, PLAIN_SAMPLES, get_cipher
from cipherops.ciphers.utils import sha256_text
from scripts.generate_datasets import _roundtrip_ok

ROOT = Path(__file__).resolve().parents[1]
DATASET_ROOT = ROOT / "datasets" / "fingerprinted"
GROUND_TRUTH = ROOT / "Pre-LLM-Ingestion" / "processed" / "cipher-ground-truth.jsonl"
MANIFEST = DATASET_ROOT / "manifest.json"

REQUIRED_FIELDS = {
    "id",
    "plaintext",
    "ciphertext",
    "cipher_family",
    "params",
    "math_ref",
    "validation",
    "difficulty",
}

# Ciphers whose ciphertext includes per-run entropy (timestamp, OAEP padding, etc.)
NON_DETERMINISTIC = {"fernet", "rsa-oaep-hybrid"}


@dataclass
class ValidationReport:
    passed: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    stats: dict[str, int] = field(default_factory=dict)

    def ok(self, msg: str) -> None:
        self.passed.append(msg)

    def warn(self, msg: str) -> None:
        self.warnings.append(msg)

    def fail(self, msg: str) -> None:
        self.errors.append(msg)

    def inc(self, key: str, n: int = 1) -> None:
        self.stats[key] = self.stats.get(key, 0) + n


def validate_registry(report: ValidationReport) -> None:
    slugs = [s.slug for s in CIPHER_REGISTRY]
    if len(slugs) != len(set(slugs)):
        report.fail("Registry contains duplicate slugs")
    else:
        report.ok(f"Registry: {len(slugs)} unique cipher variants")

    for spec in CIPHER_REGISTRY:
        math_path = ROOT / spec.math_ref
        if not math_path.is_file():
            report.fail(f"Missing math doc: {spec.math_ref} (slug={spec.slug})")
        elif math_path.stat().st_size < 50:
            report.warn(f"Math doc very short: {spec.math_ref}")

    classical = sum(1 for s in CIPHER_REGISTRY if s.era == "classical")
    modern = sum(1 for s in CIPHER_REGISTRY if s.era == "modern")
    report.ok(f"Era split: {classical} classical, {modern} modern")


def validate_manifest(report: ValidationReport) -> None:
    if not MANIFEST.is_file():
        report.fail(f"Missing manifest: {MANIFEST}")
        return

    manifest = json.loads(MANIFEST.read_text())
    registry_slugs = {s.slug for s in CIPHER_REGISTRY}
    manifest_slugs = {entry["slug"] for entry in manifest}

    missing = registry_slugs - manifest_slugs
    extra = manifest_slugs - registry_slugs
    if missing:
        report.fail(f"Manifest missing slugs: {sorted(missing)}")
    if extra:
        report.fail(f"Manifest has unknown slugs: {sorted(extra)}")
    if not missing and not extra:
        report.ok(f"Manifest aligned with registry ({len(manifest)} entries)")


def validate_ground_truth(report: ValidationReport) -> None:
    if not GROUND_TRUTH.is_file():
        report.fail(f"Missing ground truth: {GROUND_TRUTH}")
        return

    records = [json.loads(line) for line in GROUND_TRUTH.read_text().splitlines() if line.strip()]
    gt_slugs = {r["variant_slug"] for r in records}
    registry_slugs = {s.slug for s in CIPHER_REGISTRY}

    if gt_slugs != registry_slugs:
        report.fail(
            f"Ground truth slug mismatch. missing={sorted(registry_slugs - gt_slugs)} "
            f"extra={sorted(gt_slugs - registry_slugs)}"
        )
    else:
        report.ok(f"Ground truth aligned ({len(records)} records)")

    for record in records:
        spec = get_cipher(record["variant_slug"])
        if record["math_ref"] != spec.math_ref:
            report.fail(f"Ground truth math_ref mismatch for {record['variant_slug']}")
        if record["cipher_family"] != spec.family:
            report.fail(f"Ground truth family mismatch for {record['variant_slug']}")


def validate_dataset_file(path: Path, report: ValidationReport) -> int:
    slug = path.parent.name
    spec = get_cipher(slug)
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    record_count = 0

    if len(lines) != len(PLAIN_SAMPLES):
        report.fail(f"{slug}: expected {len(PLAIN_SAMPLES)} records, found {len(lines)}")

    seen_ids: set[str] = set()
    for line_no, line in enumerate(lines, start=1):
        record_count += 1
        prefix = f"{slug}:{line_no}"

        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            report.fail(f"{prefix}: invalid JSON: {exc}")
            continue

        missing = REQUIRED_FIELDS - set(record)
        if missing:
            report.fail(f"{prefix}: missing fields {sorted(missing)}")
            continue

        if record["id"] in seen_ids:
            report.fail(f"{prefix}: duplicate id {record['id']}")
        seen_ids.add(record["id"])

        if not record["id"].startswith(slug):
            report.warn(f"{prefix}: id {record['id']!r} does not start with slug {slug}")

        if record["cipher_family"] != spec.family:
            report.fail(f"{prefix}: family {record['cipher_family']!r} != {spec.family!r}")

        if record["math_ref"] != spec.math_ref:
            report.fail(f"{prefix}: math_ref mismatch")

        if record.get("era", spec.era) != spec.era:
            report.fail(f"{prefix}: era mismatch")

        validation = record["validation"]
        if validation.get("encrypt_only") != spec.encrypt_only:
            report.fail(f"{prefix}: encrypt_only flag mismatch")

        expected_hash = sha256_text(record["plaintext"])
        stored_hash = validation.get("plaintext_sha256")
        if stored_hash != expected_hash:
            report.fail(f"{prefix}: plaintext_sha256 mismatch for {record['id']}")
        else:
            report.inc("plaintext_sha256_ok")

        plaintext = record["plaintext"]
        ciphertext = record["ciphertext"]

        if not ciphertext:
            report.fail(f"{prefix}: empty ciphertext")
        if spec.encrypt_only:
            recomputed = spec.encrypt(plaintext)
            if recomputed != ciphertext:
                report.fail(f"{prefix}: encrypt_only digest mismatch for {record['id']}")
            else:
                report.inc("encrypt_only_ok")
            if validation.get("roundtrip_verified") is True:
                report.fail(f"{prefix}: encrypt_only should not be roundtrip_verified")
        else:
            decrypted = spec.decrypt(ciphertext)
            if not _roundtrip_ok(plaintext, decrypted, spec.family):
                report.fail(
                    f"{prefix}: roundtrip failed "
                    f"plaintext={plaintext!r} decrypted={decrypted!r}"
                )
            else:
                report.inc("roundtrip_ok")
            if slug not in NON_DETERMINISTIC:
                reencrypted = spec.encrypt(plaintext)
                if reencrypted != ciphertext:
                    report.fail(f"{prefix}: re-encrypt mismatch (non-deterministic output?)")
                else:
                    report.inc("reencrypt_ok")
            else:
                report.inc("reencrypt_skipped")
            if validation.get("roundtrip_verified") is not True:
                report.fail(f"{prefix}: roundtrip_verified should be true")

        report.inc("records_checked")

    return record_count


def validate_datasets(report: ValidationReport) -> None:
    dataset_files = sorted(DATASET_ROOT.glob("*/data.jsonl"))
    registry_slugs = {s.slug for s in CIPHER_REGISTRY}
    dataset_slugs = {p.parent.name for p in dataset_files}

    missing_dirs = registry_slugs - dataset_slugs
    orphan_dirs = dataset_slugs - registry_slugs
    if missing_dirs:
        report.fail(f"Missing dataset directories: {sorted(missing_dirs)}")
    if orphan_dirs:
        report.fail(f"Orphan dataset directories: {sorted(orphan_dirs)}")

    total_records = 0
    for path in dataset_files:
        total_records += validate_dataset_file(path, report)

    report.ok(f"Dataset files scanned: {len(dataset_files)} ({total_records} total records)")


def validate_plaintext_corpus(report: ValidationReport) -> None:
    """Ensure all datasets use the canonical PLAIN_SAMPLES corpus in order."""
    for path in sorted(DATASET_ROOT.glob("*/data.jsonl")):
        slug = path.parent.name
        lines = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
        for idx, (record, expected) in enumerate(zip(lines, PLAIN_SAMPLES)):
            if record["plaintext"] != expected:
                report.fail(
                    f"{slug}: plaintext sample {idx + 1} deviates from PLAIN_SAMPLES corpus"
                )
                break
    report.ok(f"Plaintext corpus: {len(PLAIN_SAMPLES)} canonical samples verified across datasets")


def validate_live_registry_roundtrip(report: ValidationReport) -> None:
    """Fresh encrypt/decrypt from registry (independent of stored ciphertext)."""
    for spec in CIPHER_REGISTRY:
        for idx, plaintext in enumerate(PLAIN_SAMPLES[:3], start=1):
            ciphertext = spec.encrypt(plaintext)
            if spec.encrypt_only:
                if not ciphertext:
                    report.fail(f"{spec.slug}: live encrypt_only produced empty output sample {idx}")
                continue
            decrypted = spec.decrypt(ciphertext)
            if not _roundtrip_ok(plaintext, decrypted, spec.family):
                report.fail(
                    f"{spec.slug}: live roundtrip failed sample {idx} "
                    f"decrypted={decrypted!r}"
                )
    report.ok("Live registry roundtrip: first 3 PLAIN_SAMPLES per cipher passed")


def print_report(report: ValidationReport) -> None:
    print("=" * 72)
    print("COMPREHENSIVE VALIDATION REPORT")
    print("=" * 72)
    print(f"\nPASSED ({len(report.passed)}):")
    for item in report.passed:
        print(f"  [OK] {item}")

    if report.warnings:
        print(f"\nWARNINGS ({len(report.warnings)}):")
        for item in report.warnings:
            print(f"  [WARN] {item}")

    if report.errors:
        print(f"\nERRORS ({len(report.errors)}):")
        for item in report.errors:
            print(f"  [FAIL] {item}")

    if report.stats:
        print(f"\nRECORD-LEVEL STATS:")
        for key in sorted(report.stats):
            print(f"  {key}: {report.stats[key]}")

    print("\n" + "=" * 72)
    if report.errors:
        print(f"RESULT: FAILED ({len(report.errors)} errors, {len(report.warnings)} warnings)")
    else:
        print(f"RESULT: PASSED ({len(report.passed)} checks, {len(report.warnings)} warnings)")
    print("=" * 72)


def main() -> int:
    report = ValidationReport()
    validate_registry(report)
    validate_manifest(report)
    validate_ground_truth(report)
    validate_plaintext_corpus(report)
    validate_datasets(report)
    validate_live_registry_roundtrip(report)
    print_report(report)
    return 1 if report.errors else 0


if __name__ == "__main__":
    sys.exit(main())
