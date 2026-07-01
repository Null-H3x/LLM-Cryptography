#!/usr/bin/env python3
"""Generate constraint findings and run validated re-propagation loop."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from cipherops.constraints.pipeline import (
    build_corpus_configs,
    run_findings_loop,
    serialize_pipeline_outputs,
)

OUT_ROOT = ROOT / "datasets" / "constraint-findings"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--max-rounds",
        type=int,
        default=10,
        help="Maximum validation/re-propagation rounds per corpus (default 10)",
    )
    parser.add_argument(
        "--corpus",
        action="append",
        dest="corpora",
        help="Limit to specific corpus slug(s); repeatable",
    )
    args = parser.parse_args()

    configs = build_corpus_configs(ROOT)
    if args.corpora:
        allowed = set(args.corpora)
        configs = [c for c in configs if c.slug in allowed]
        if not configs:
            print(f"No matching corpora for {sorted(allowed)}", file=sys.stderr)
            return 1

    OUT_ROOT.mkdir(parents=True, exist_ok=True)
    manifest: list[dict] = []

    for config in configs:
        print(f"\n==> {config.slug} ({config.propagator})")
        result = run_findings_loop(config, max_rounds=args.max_rounds)
        out_dir = OUT_ROOT / config.slug
        out_dir.mkdir(parents=True, exist_ok=True)

        lines, history = serialize_pipeline_outputs(result)
        findings_path = out_dir / "findings.jsonl"
        findings_path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")

        validated_path = out_dir / "validated.jsonl"
        validated_lines = [
            json.dumps({**f, "corpus": result.corpus, "status": "validated"}, ensure_ascii=False)
            for f in result.final_validated
        ]
        validated_path.write_text(
            "\n".join(validated_lines) + ("\n" if validated_lines else ""),
            encoding="utf-8",
        )

        history_path = out_dir / "history.json"
        history_path.write_text(json.dumps(history, indent=2) + "\n", encoding="utf-8")

        last = result.rounds[-1] if result.rounds else None
        print(
            f"    rounds={len(result.rounds)} "
            f"findings={last.findings_count if last else 0} "
            f"validated={len(result.final_validated)} "
            f"conflicts={result.remaining_conflicts} "
            f"converged={result.converged}"
        )

        manifest.append(
            {
                "slug": config.slug,
                "propagator": config.propagator,
                "description": config.description,
                "findings_path": str(findings_path.relative_to(ROOT)),
                "validated_path": str(validated_path.relative_to(ROOT)),
                "history_path": str(history_path.relative_to(ROOT)),
                "rounds": len(result.rounds),
                "validated_count": len(result.final_validated),
                "remaining_conflicts": result.remaining_conflicts,
                "converged": result.converged,
            }
        )

    manifest_path = OUT_ROOT / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"\nwrote manifest: {manifest_path} ({len(manifest)} corpora)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
