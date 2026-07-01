#!/usr/bin/env python3
"""Validate constraint findings datasets against live propagators and corpora."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from cipherops.constraints.domain import Finding, FindingKind, FindingsMap
from cipherops.constraints.pipeline import (
    REQUIRED_FINDING_KEYS,
    build_corpus_configs,
    finding_fingerprint,
    run_findings_loop,
    validate_finding,
    run_propagator,
)

OUT_ROOT = ROOT / "datasets" / "constraint-findings"
MANIFEST = OUT_ROOT / "manifest.json"


def _load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def validate_record(record: dict, line_no: int, slug: str) -> list[str]:
    errors: list[str] = []
    prefix = f"{slug}:findings:{line_no}"
    missing = REQUIRED_FINDING_KEYS - set(record.keys())
    if missing:
        errors.append(f"{prefix}: missing keys {sorted(missing)}")
        return errors

    if record.get("confidence") not in {"hard", "propagated", "heuristic"}:
        errors.append(f"{prefix}: invalid confidence {record.get('confidence')!r}")

    fp = record.get("fingerprint")
    core = {k: record[k] for k in REQUIRED_FINDING_KEYS}
    expected_fp = finding_fingerprint(core)
    if fp and fp != expected_fp:
        errors.append(f"{prefix}: fingerprint mismatch")

    return errors


def validate_corpus(slug: str, entry: dict, configs: dict) -> list[str]:
    errors: list[str] = []
    config = configs.get(slug)
    if config is None:
        errors.append(f"{slug}: no corpus config for re-validation")
        return errors

    findings_path = ROOT / entry["findings_path"]
    validated_path = ROOT / entry["validated_path"]
    history_path = ROOT / entry["history_path"]

    for label, path in (
        ("findings", findings_path),
        ("validated", validated_path),
        ("history", history_path),
    ):
        if not path.is_file():
            errors.append(f"{slug}: missing {label} file {path.relative_to(ROOT)}")

    if errors:
        return errors

    findings_rows = _load_jsonl(findings_path)
    for i, row in enumerate(findings_rows, start=1):
        errors.extend(validate_record(row, i, slug))

    # Re-run loop live and compare counts / convergence
    live = run_findings_loop(config, max_rounds=10)
    if live.remaining_conflicts > 0:
        errors.append(f"{slug}: live loop reports {live.remaining_conflicts} conflict(s)")

    if entry.get("converged") is True and not live.converged:
        errors.append(f"{slug}: stored converged=true but live loop did not converge")

    if entry.get("validated_count", -1) != len(live.final_validated):
        errors.append(
            f"{slug}: validated_count mismatch stored={entry.get('validated_count')} "
            f"live={len(live.final_validated)}"
        )

    # Spot-check: re-validate round-0 findings against source state
    round0 = [r for r in findings_rows if r.get("round") == 0]
    if round0:
        initial_findings = FindingsMap(
            findings=[
                Finding(
                    kind=r["kind"],
                    source=r["source"],
                    confidence=r["confidence"],
                    data=r.get("data", {}),
                )
                for r in round0
            ]
        )
        live_r0 = run_propagator(config.state, config.propagator)
        if len(live_r0.findings) != len(initial_findings.findings):
            errors.append(
                f"{slug}: round-0 finding count drift "
                f"stored={len(initial_findings.findings)} live={len(live_r0.findings)}"
            )
        rejected = 0
        for f in initial_findings.findings:
            vf = validate_finding(f, config.state, config.propagator)
            if vf.status == "rejected":
                rejected += 1
        if rejected:
            errors.append(f"{slug}: {rejected} stored round-0 finding(s) fail live validation")

    history = json.loads(history_path.read_text(encoding="utf-8"))
    if history.get("corpus") != slug:
        errors.append(f"{slug}: history corpus field mismatch")
    if "final_validated" in history:
        errors.append(f"{slug}: history must not embed final_validated (use validated.jsonl)")

    return errors


def main() -> int:
    if not MANIFEST.is_file():
        print(f"Missing manifest: {MANIFEST}", file=sys.stderr)
        print("Run scripts/generate_constraint_findings.py first.", file=sys.stderr)
        return 1

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    configs = {c.slug: c for c in build_corpus_configs(ROOT)}

    all_errors: list[str] = []
    checked = 0
    for entry in manifest:
        slug = entry["slug"]
        errs = validate_corpus(slug, entry, configs)
        all_errors.extend(errs)
        checked += 1
        status = "OK" if not errs else "FAIL"
        print(f"  [{status}] {slug} ({len(errs)} issue(s))")

    print("=" * 72)
    if all_errors:
        print(f"VALIDATION FAILED ({len(all_errors)} errors across {checked} corpora)")
        for err in all_errors:
            print(f"  - {err}")
        return 1

    print(f"VALIDATION PASSED ({checked} corpora)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
