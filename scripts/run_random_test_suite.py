#!/usr/bin/env python3
"""Run comprehensive function tests against the random-test cipher corpus."""

from __future__ import annotations

import argparse
import json
import sys
import traceback
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cipherops.analysis.classifier import classify_ciphertext
from cipherops.analysis.profile import analyze_ciphertext
from cipherops.ciphers.registry import CIPHER_REGISTRY, get_cipher
from cipherops.ciphers.utils import clean_alpha
from cipherops.constraints.adhoc import build_custom_config, propagator_for_slug
from cipherops.constraints.pipeline import run_findings_loop
from cipherops.constraints.prepare_run import prepare_run
from scripts.generate_datasets import _roundtrip_ok
from scripts.random_test_lib import (
    DEFAULT_SEED,
    ENCRYPT_ONLY_SLUGS,
    NON_DETERMINISTIC,
    RANDOM_TEST_ROOT_NAME,
    family_match,
    is_list_ciphertext,
)

ROOT = Path(__file__).resolve().parents[1]

PROFILE_REQUIRED_KEYS = {"stream", "fingerprint", "frequency", "kasiski", "attacks", "analysis_guidance"}


@dataclass
class CaseResult:
    slug: str
    record_id: str
    cipher_family: str
    tests: dict[str, str] = field(default_factory=dict)
    breaks: list[dict[str, Any]] = field(default_factory=list)
    soft_fails: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class SuiteReport:
    started_at: str
    finished_at: str = ""
    seed: int = DEFAULT_SEED
    corpus_root: str = ""
    total_records: int = 0
    total_breaks: int = 0
    total_soft_fails: int = 0
    break_summary: dict[str, int] = field(default_factory=dict)
    soft_fail_summary: dict[str, int] = field(default_factory=dict)
    cases: list[CaseResult] = field(default_factory=list)
    passed_all: list[str] = field(default_factory=list)


def _load_corpus(corpus_root: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in sorted(corpus_root.glob("*/data.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                records.append(json.loads(line))
    return records


def _add_break(case: CaseResult, test: str, error: str, **extra: Any) -> None:
    case.tests[test] = "break"
    payload = {"test": test, "error": error, **extra}
    case.breaks.append(payload)


def _add_soft(case: CaseResult, test: str, detail: str, **extra: Any) -> None:
    case.tests[test] = "soft_fail"
    case.soft_fails.append({"test": test, "detail": detail, **extra})


def _mark_ok(case: CaseResult, test: str) -> None:
    case.tests.setdefault(test, "ok")


def _run_pipeline_smoke(case: CaseResult, record: dict[str, Any], spec) -> None:
    slug = record["slug"]
    propagator = propagator_for_slug(slug)
    if propagator is None:
        case.notes.append("pipeline_skipped:no_propagator")
        return

    ciphertext = record.get("ciphertext")
    ct_str = json.dumps(ciphertext) if isinstance(ciphertext, list) else str(ciphertext or "")
    if propagator == "stream_extension" and not clean_alpha(ct_str):
        case.notes.append("pipeline_skipped:non_alpha_stream_ciphertext")
        return

    try:
        payload: dict[str, Any] = {
            "source": "custom",
            "propagator": propagator,
            "ciphertext": record.get("ciphertext"),
            "plaintext": record.get("plaintext"),
            "slug": f"random-test/{slug}/{record['id']}",
            "hypothesis": dict(spec.params),
        }
        if propagator == "dynamic_perm":
            seed = int(spec.params.get("prng_seed", 42))
            payload["seed_candidates"] = [seed - 1, seed, seed + 1]
        config = build_custom_config(payload, root=ROOT)
        result = run_findings_loop(config, max_rounds=2)
        _mark_ok(case, "pipeline_smoke")
        stop_status = result.stop.status if result.stop else "running"
        case.notes.append(
            f"pipeline_converged={result.converged} stop={stop_status} conflicts={result.remaining_conflicts}"
        )
    except Exception as exc:
        _add_break(
            case,
            "pipeline_smoke",
            f"{type(exc).__name__}: {exc}",
            traceback=traceback.format_exc(),
        )


def run_case(record: dict[str, Any]) -> CaseResult:
    slug = record["slug"]
    spec = get_cipher(slug)
    case = CaseResult(
        slug=slug,
        record_id=record["id"],
        cipher_family=record["cipher_family"],
    )

    plaintext = record["plaintext"]
    stored_ct = record.get("ciphertext")

    # --- registry lookup ---
    try:
        looked_up = get_cipher(slug)
        if looked_up.slug != slug:
            _add_break(case, "registry_lookup", "slug mismatch")
        else:
            _mark_ok(case, "registry_lookup")
    except Exception as exc:
        _add_break(case, "registry_lookup", f"{type(exc).__name__}: {exc}")
        return case

    # --- encrypt ---
    try:
        ciphertext = spec.encrypt(plaintext)
        if not ciphertext and ciphertext != 0:
            _add_break(case, "encrypt", "empty ciphertext")
        else:
            _mark_ok(case, "encrypt")
    except Exception as exc:
        _add_break(case, "encrypt", f"{type(exc).__name__}: {exc}", traceback=traceback.format_exc())
        return case

    # --- stored ciphertext consistency ---
    if stored_ct is None:
        _add_break(case, "corpus_ciphertext", "missing stored ciphertext from generation")
    elif serialize := (json.dumps(ciphertext, ensure_ascii=True) if isinstance(ciphertext, list) else ciphertext):
        stored_s = json.dumps(stored_ct, ensure_ascii=True) if isinstance(stored_ct, list) else stored_ct
        if slug not in NON_DETERMINISTIC and not spec.encrypt_only and serialize != stored_s:
            _add_soft(
                case,
                "corpus_ciphertext",
                "live encrypt differs from stored corpus ciphertext",
            )
        else:
            _mark_ok(case, "corpus_ciphertext")

    # --- decrypt / roundtrip ---
    if spec.encrypt_only or slug in ENCRYPT_ONLY_SLUGS:
        case.notes.append("roundtrip_skipped:encrypt_only")
        try:
            digest = spec.encrypt(plaintext)
            if digest:
                _mark_ok(case, "encrypt_only_digest")
            else:
                _add_break(case, "encrypt_only_digest", "empty digest")
        except Exception as exc:
            _add_break(case, "encrypt_only_digest", f"{type(exc).__name__}: {exc}")
    else:
        try:
            decrypted = spec.decrypt(ciphertext)
            if _roundtrip_ok(plaintext, decrypted, spec.family):
                _mark_ok(case, "decrypt_roundtrip")
            else:
                _add_break(
                    case,
                    "decrypt_roundtrip",
                    "roundtrip mismatch",
                    plaintext=plaintext[:80],
                    decrypted=str(decrypted)[:80],
                )
        except Exception as exc:
            _add_break(
                case,
                "decrypt_roundtrip",
                f"{type(exc).__name__}: {exc}",
                traceback=traceback.format_exc(),
            )

        if slug not in NON_DETERMINISTIC:
            try:
                reenc = spec.encrypt(plaintext)
                if reenc == ciphertext:
                    _mark_ok(case, "reencrypt_deterministic")
                else:
                    _add_soft(case, "reencrypt_deterministic", "re-encrypt output differs")
            except Exception as exc:
                _add_break(case, "reencrypt_deterministic", f"{type(exc).__name__}: {exc}")

    ct_for_analysis: str | list = ciphertext
    if is_list_ciphertext(ciphertext):
        ct_for_analysis = ciphertext
    elif not isinstance(ciphertext, str):
        ct_for_analysis = str(ciphertext)

    # --- profile ---
    try:
        profile = analyze_ciphertext(
            ct_for_analysis,
            cipher_family=spec.family,
            era=spec.era,
            status="solved",
            params=spec.params,
            deck_size=spec.params.get("deck_size") or spec.params.get("alphabet_size"),
        )
        missing = PROFILE_REQUIRED_KEYS - set(profile)
        if missing:
            _add_break(case, "profile", f"missing keys: {sorted(missing)}")
        else:
            _mark_ok(case, "profile")
    except Exception as exc:
        _add_break(case, "profile", f"{type(exc).__name__}: {exc}", traceback=traceback.format_exc())

    # --- classifier ---
    classification: dict[str, Any] | None = None
    try:
        if is_list_ciphertext(ct_for_analysis):
            classification = classify_ciphertext(ciphertexts=[ct_for_analysis], deck_size=spec.params.get("deck_size"))
        else:
            classification = classify_ciphertext(str(ct_for_analysis), full=True)
        if not classification.get("hypotheses"):
            _add_break(case, "classifier", "no hypotheses returned")
        else:
            _mark_ok(case, "classifier")
    except Exception as exc:
        _add_break(case, "classifier", f"{type(exc).__name__}: {exc}", traceback=traceback.format_exc())

    # --- classifier family hit (soft) ---
    if classification and classification.get("hypotheses"):
        top_families = [h.get("family", "") for h in classification["hypotheses"][:3]]
        if any(family_match(spec.family, fam) for fam in top_families):
            _mark_ok(case, "classifier_family_hit")
        else:
            _add_soft(
                case,
                "classifier_family_hit",
                f"expected {spec.family}, top-3={top_families}",
                top_hypotheses=[h.get("label") for h in classification["hypotheses"][:3]],
            )

    # --- prepare_run ---
    if classification and classification.get("hypotheses"):
        try:
            prep_ct = None if is_list_ciphertext(ct_for_analysis) else str(ct_for_analysis)
            prep_decks = [ct_for_analysis] if is_list_ciphertext(ct_for_analysis) else None
            prepared = prepare_run(
                classification,
                hypothesis_index=0,
                ciphertext=prep_ct,
                ciphertexts=prep_decks,
            )
            if "steps" not in prepared:
                _add_soft(case, "prepare_run", "missing steps in prepare_run output")
            else:
                _mark_ok(case, "prepare_run")
        except Exception as exc:
            _add_break(case, "prepare_run", f"{type(exc).__name__}: {exc}", traceback=traceback.format_exc())
    else:
        case.notes.append("prepare_run_skipped:no_classification")

    # --- pipeline smoke (propagator-backed ciphers only) ---
    _run_pipeline_smoke(case, {**record, "ciphertext": ct_for_analysis}, spec)

    return case


def run_suite(corpus_root: Path, *, seed: int = DEFAULT_SEED) -> SuiteReport:
    started = datetime.now(timezone.utc).isoformat()
    records = _load_corpus(corpus_root)
    report = SuiteReport(
        started_at=started,
        seed=seed,
        corpus_root=str(corpus_root.relative_to(ROOT)),
        total_records=len(records),
    )

    for record in records:
        case = run_case(record)
        report.cases.append(case)
        if case.breaks:
            report.total_breaks += len(case.breaks)
            for br in case.breaks:
                key = f"{case.slug}:{br['test']}"
                report.break_summary[key] = report.break_summary.get(key, 0) + 1
        else:
            report.passed_all.append(case.record_id)
        for sf in case.soft_fails:
            report.total_soft_fails += 1
            key = f"{case.slug}:{sf['test']}"
            report.soft_fail_summary[key] = report.soft_fail_summary.get(key, 0) + 1

    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report


def write_reports(report: SuiteReport, output_root: Path) -> None:
    results_dir = output_root / "results"
    results_dir.mkdir(parents=True, exist_ok=True)

    serializable = {
        "started_at": report.started_at,
        "finished_at": report.finished_at,
        "seed": report.seed,
        "corpus_root": report.corpus_root,
        "total_records": report.total_records,
        "total_breaks": report.total_breaks,
        "total_soft_fails": report.total_soft_fails,
        "break_summary": report.break_summary,
        "soft_fail_summary": report.soft_fail_summary,
        "passed_all": report.passed_all,
        "cases": [asdict(c) for c in report.cases],
    }
    (results_dir / "report.json").write_text(json.dumps(serializable, indent=2), encoding="utf-8")

    lines = [
        "# Random Test Suite Report",
        "",
        f"- **Started:** {report.started_at}",
        f"- **Finished:** {report.finished_at}",
        f"- **Seed:** {report.seed}",
        f"- **Records:** {report.total_records}",
        f"- **Hard breaks:** {report.total_breaks}",
        f"- **Soft fails:** {report.total_soft_fails}",
        f"- **Clean records:** {len(report.passed_all)}",
        "",
    ]

    if report.break_summary:
        lines.extend(["## Hard breaks (exceptions / roundtrip failures)", ""])
        for key, count in sorted(report.break_summary.items()):
            lines.append(f"- `{key}` × {count}")
        lines.append("")
        lines.extend(["### Break details", ""])
        for case in report.cases:
            if not case.breaks:
                continue
            lines.append(f"#### {case.record_id} ({case.slug})")
            for br in case.breaks:
                lines.append(f"- **{br['test']}**: {br['error']}")
            lines.append("")

    if report.soft_fail_summary:
        lines.extend(["## Soft fails (misclassification / non-fatal)", ""])
        for key, count in sorted(report.soft_fail_summary.items()):
            lines.append(f"- `{key}` × {count}")
        lines.append("")

    if not report.break_summary and not report.soft_fail_summary:
        lines.append("All tests passed with no soft failures.")

    (results_dir / "report.md").write_text("\n".join(lines), encoding="utf-8")
    (results_dir / "latest-run.txt").write_text(report.finished_at, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--corpus",
        type=Path,
        default=ROOT / RANDOM_TEST_ROOT_NAME / "corpus",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / RANDOM_TEST_ROOT_NAME,
    )
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    args = parser.parse_args()

    if not args.corpus.is_dir():
        print(f"Corpus not found: {args.corpus}. Run generate_random_test_corpus.py first.", file=sys.stderr)
        return 1

    report = run_suite(args.corpus, seed=args.seed)
    write_reports(report, args.output)

    print(f"Random test suite complete: {report.total_records} records")
    print(f"Hard breaks: {report.total_breaks}")
    print(f"Soft fails: {report.total_soft_fails}")
    print(f"Report: {args.output / 'results' / 'report.md'}")
    return 1 if report.total_breaks else 0


if __name__ == "__main__":
    raise SystemExit(main())
